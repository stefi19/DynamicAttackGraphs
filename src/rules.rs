// Attack graph rules implementation
// Translates MulVAL-style Datalog rules into differential dataflow operators
//
// STRATIFIED NEGATION:
// Firewall rules use antijoin to implement "NOT blocked" semantics.
// This is safe because firewall rules are base facts (stratum 0) and
// effective_access is derived (stratum 1). The negation is stratified.
//
// CYCLE HANDLING:
// The iterate() operator computes a fixed point. The distinct() call inside
// ensures that each derived fact appears exactly once. When cycles try to
// re-derive existing facts, the diff is 0 (+1 and -1 cancel), causing
// termination. This is mathematically equivalent to semi-naive evaluation.

use differential_dataflow::collection::Collection;
use differential_dataflow::operators::iterate::Iterate;
use differential_dataflow::operators::join::Join;
use differential_dataflow::operators::reduce::Threshold;
use differential_dataflow::operators::Consolidate;
use timely::dataflow::Scope;

use crate::schema::*;

// Main function that builds the attack graph dataflow
// Takes input collections and returns derived collections
//
// The dataflow implements these Datalog rules:
//
//   effectiveAccess(S, D, Svc) :-
//       networkAccess(S, D, Svc),
//       NOT firewallDeny(S, D, Svc).
//
//   execCode(A, H, P) :- attackerLocation(A, H, P).
//   execCode(A, Dst, P) :-
//       execCode(A, Src, _),
//       effectiveAccess(Src, Dst, Svc),
//       vulnerability(Dst, _, Svc, P).
//
//   ownsMachine(A, H) :- execCode(A, H, root).
//   goalReached(A, T) :- attackerGoal(A, T), ownsMachine(A, T).
//
pub fn build_attack_graph<G>(
    vulnerability_collection: &Collection<G, VulnerabilityRecord>,
    network_access_collection: &Collection<G, NetworkAccessRule>,
    firewall_rules_collection: &Collection<G, FirewallRuleRecord>,
    attacker_positions_collection: &Collection<G, AttackerStartingPosition>,
    attacker_goals_collection: &Collection<G, AttackerTargetGoal>,
) -> (
    Collection<G, AttackerCodeExecution>,
    Collection<G, AttackerOwnsMachine>,
    Collection<G, AttackerGoalReached>,
)
where
    G: Scope,
    G::Timestamp: differential_dataflow::lattice::Lattice + Ord,
{
    // =========================================================================
    // STRATUM 0: Base facts (firewall rules)
    // STRATUM 1: Effective access (uses negation over firewall rules)
    // STRATUM 2: Code execution (recursive, uses effective access)
    // STRATUM 3: Ownership and goals (derived from code execution)
    // =========================================================================

    // STRATUM 1: Compute effective network access using antijoin
    // This implements: effectiveAccess(S,D,Svc) :- network(S,D,Svc), NOT deny(S,D,Svc)
    //
    // The antijoin operator removes from the left collection any tuple whose
    // key appears in the right collection. This is stratified negation because
    // firewall rules are base facts and don't depend on derived facts.
    
    let network_access_keyed_by_route = network_access_collection
        .map(|rule| {
            let route_key = (rule.source_host.clone(), rule.destination_host.clone(), rule.service_name.clone());
            (route_key, rule)
        });
    
    let blocked_route_keys = firewall_rules_collection
        .filter(|rule| rule.rule_action == FirewallRuleAction::Deny)
        .map(|rule| (rule.source_zone.clone(), rule.destination_host.clone(), rule.service_name.clone()))
        .distinct();
    
    let effective_network_access = network_access_keyed_by_route
        .antijoin(&blocked_route_keys)
        .map(|(_, original_rule)| EffectiveNetworkAccess {
            source_host: original_rule.source_host,
            destination_host: original_rule.destination_host,
            service_name: original_rule.service_name,
        });

    // STRATUM 2: Compute code execution with fixed-point iteration
    // Base case: attacker starts at their initial location
    let initial_code_execution = attacker_positions_collection
        .map(|position| AttackerCodeExecution {
            attacker_id: position.attacker_id,
            compromised_host: position.starting_host,
            obtained_privilege: position.initial_privilege,
        });

    // Prepare indexed collections for efficient joins inside iteration
    let access_indexed_by_source = effective_network_access
        .map(|access| (access.source_host.clone(), (access.destination_host.clone(), access.service_name.clone())));
    
    let vulnerabilities_indexed_by_host_service = vulnerability_collection
        .map(|vuln| ((vuln.host_name.clone(), vuln.affected_service.clone()), vuln.privilege_gained_on_exploit.clone()));

    // Fixed-point iteration for transitive attack propagation
    // CYCLE SAFETY: distinct() ensures each fact appears once. When a cycle
    // tries to re-derive a fact, the +1 diff is cancelled by the existing -1
    // from the previous iteration, producing net diff = 0, which stops propagation.
    let all_code_executions = initial_code_execution.iterate(|current_executions| {
        let access_in_scope = access_indexed_by_source.enter(&current_executions.scope());
        let vulns_in_scope = vulnerabilities_indexed_by_host_service.enter(&current_executions.scope());
        
        // For each compromised host, find reachable destinations
        let reachable_destinations = current_executions
            .map(|exec| (exec.compromised_host.clone(), exec.attacker_id.clone()))
            .join(&access_in_scope)
            .map(|(_source, (attacker_id, (destination, service)))| {
                ((destination, service), attacker_id)
            });
        
        // Join with vulnerabilities to find exploitable targets
        let newly_compromised_hosts = reachable_destinations
            .join(&vulns_in_scope)
            .map(|((host, _service), (attacker_id, privilege))| AttackerCodeExecution {
                attacker_id,
                compromised_host: host,
                obtained_privilege: privilege,
            });
        
        // Combine and deduplicate - THIS IS CRITICAL FOR CYCLE TERMINATION
        // The distinct() ensures fixed-point convergence
        newly_compromised_hosts
            .concat(current_executions)
            .distinct()
    });

    // STRATUM 3: Derive ownership (root privilege implies ownership)
    let machines_owned_by_attackers = all_code_executions
        .filter(|exec| exec.obtained_privilege == PrivilegeLevel::Root)
        .map(|exec| AttackerOwnsMachine {
            attacker_id: exec.attacker_id,
            owned_host: exec.compromised_host,
        })
        .distinct();

    // STRATUM 3: Check goal reachability
    let owned_machine_keys = machines_owned_by_attackers
        .map(|owned| (owned.attacker_id.clone(), owned.owned_host.clone()))
        .distinct();
    
    let goals_keyed = attacker_goals_collection
        .map(|goal| ((goal.attacker_id.clone(), goal.target_host_name.clone()), goal));
    
    let successfully_reached_goals = goals_keyed
        .semijoin(&owned_machine_keys)
        .map(|(_, goal)| AttackerGoalReached {
            attacker_id: goal.attacker_id,
            reached_target: goal.target_host_name,
        });

    // Consolidate to merge any duplicate diffs before output
    (
        all_code_executions.consolidate(),
        machines_owned_by_attackers.consolidate(),
        successfully_reached_goals.consolidate(),
    )
}

// Alternative version with bounded iteration depth
// Useful when you want to limit how many hops the attacker can make
pub fn build_attack_graph_with_max_hops<G>(
    vulnerability_collection: &Collection<G, VulnerabilityRecord>,
    network_access_collection: &Collection<G, NetworkAccessRule>,
    attacker_positions_collection: &Collection<G, AttackerStartingPosition>,
    attacker_goals_collection: &Collection<G, AttackerTargetGoal>,
    maximum_attack_hops: usize,
) -> (
    Collection<G, AttackerCodeExecution>,
    Collection<G, AttackerOwnsMachine>,
    Collection<G, AttackerGoalReached>,
)
where
    G: Scope,
    G::Timestamp: differential_dataflow::lattice::Lattice + Ord,
{
    // Start with initial attacker positions
    let mut current_code_executions = attacker_positions_collection
        .map(|position| AttackerCodeExecution {
            attacker_id: position.attacker_id,
            compromised_host: position.starting_host,
            obtained_privilege: position.initial_privilege,
        });

    // Prepare indexed collections for joins
    let network_access_by_source = network_access_collection
        .map(|access| (access.source_host.clone(), (access.destination_host.clone(), access.service_name.clone())));
    
    let vulnerabilities_by_host_and_service = vulnerability_collection
        .map(|vuln| ((vuln.host_name.clone(), vuln.affected_service.clone()), vuln.privilege_gained_on_exploit.clone()));

    // Expand attack graph for each hop
    for _hop_number in 0..maximum_attack_hops {
        let new_executions_this_hop = current_code_executions
            .map(|execution| (execution.compromised_host.clone(), execution.attacker_id.clone()))
            .join(&network_access_by_source)
            .map(|(_source, (attacker_id, (destination, service)))| {
                ((destination, service), attacker_id)
            })
            .join(&vulnerabilities_by_host_and_service)
            .map(|((host, _service), (attacker_id, privilege))| AttackerCodeExecution {
                attacker_id,
                compromised_host: host,
                obtained_privilege: privilege,
            });
        
        current_code_executions = current_code_executions.concat(&new_executions_this_hop).distinct();
    }

    // Compute owned machines
    let machines_owned = current_code_executions
        .filter(|execution| execution.obtained_privilege == PrivilegeLevel::Root)
        .map(|execution| AttackerOwnsMachine {
            attacker_id: execution.attacker_id,
            owned_host: execution.compromised_host,
        })
        .distinct();

    // Check if goals are reached
    let owned_keys = machines_owned
        .map(|owned| (owned.attacker_id.clone(), owned.owned_host.clone()))
        .distinct();
    
    let goals_indexed = attacker_goals_collection
        .map(|goal| ((goal.attacker_id.clone(), goal.target_host_name.clone()), goal));
    
    let goals_reached = goals_indexed
        .semijoin(&owned_keys)
        .map(|(_, goal)| AttackerGoalReached {
            attacker_id: goal.attacker_id,
            reached_target: goal.target_host_name,
        });

    (current_code_executions, machines_owned, goals_reached)
}
