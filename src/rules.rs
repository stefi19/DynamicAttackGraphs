// Attack graph rules implementation
// Translates MulVAL-style Datalog rules into differential dataflow operators

use differential_dataflow::collection::Collection;
use differential_dataflow::operators::iterate::Iterate;
use differential_dataflow::operators::join::Join;
use differential_dataflow::operators::reduce::Threshold;
use differential_dataflow::operators::Consolidate;
use timely::dataflow::Scope;

use crate::schema::*;

// Main function that builds the attack graph dataflow
// Takes input collections and returns derived collections
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
    // Step 1: Compute effective network access by removing blocked connections
    // effective_access = network_access - blocked_by_firewall
    
    // Index network access by (source, destination, service) for the anti-join
    let network_access_with_key = network_access_collection
        .map(|network_rule| ((network_rule.source_host.clone(), network_rule.destination_host.clone(), network_rule.service_name.clone()), network_rule));
    
    // Get the keys of all denied connections from firewall rules
    let denied_connection_keys = firewall_rules_collection
        .filter(|firewall_rule| firewall_rule.rule_action == FirewallRuleAction::Deny)
        .map(|firewall_rule| (firewall_rule.source_zone.clone(), firewall_rule.destination_host.clone(), firewall_rule.service_name.clone()))
        .distinct();
    
    // Remove denied connections using anti-join
    let effective_network_access = network_access_with_key
        .antijoin(&denied_connection_keys)
        .map(|(_, original_rule)| EffectiveNetworkAccess {
            source_host: original_rule.source_host,
            destination_host: original_rule.destination_host,
            service_name: original_rule.service_name,
        });

    // Step 2: Initial code execution comes from attacker starting positions
    // execCode(attacker, host, privilege) :- attackerLocated(attacker, host, privilege)
    
    let initial_code_execution = attacker_positions_collection
        .map(|attacker_position| AttackerCodeExecution {
            attacker_id: attacker_position.attacker_id,
            compromised_host: attacker_position.starting_host,
            obtained_privilege: attacker_position.initial_privilege,
        });

    // Step 3: Compute transitive attack propagation using iteration
    // This is the recursive rule:
    // execCode(attacker, dst, priv) :-
    //     execCode(attacker, src, _),
    //     effectiveAccess(src, dst, service),
    //     vulExists(dst, _, service, priv)
    
    // Prepare access collection indexed by source host
    let network_access_by_source = effective_network_access
        .map(|access| (access.source_host.clone(), (access.destination_host.clone(), access.service_name.clone())));
    
    // Prepare vulnerabilities indexed by (host, service)
    let vulnerabilities_by_host_and_service = vulnerability_collection
        .map(|vuln| ((vuln.host_name.clone(), vuln.affected_service.clone()), vuln.privilege_gained_on_exploit.clone()));

    // Iterate until no new code executions are found (fixpoint)
    let all_code_executions = initial_code_execution.iterate(|current_executions| {
        // Bring external collections into the iteration scope
        let access_in_scope = network_access_by_source.enter(&current_executions.scope());
        let vulns_in_scope = vulnerabilities_by_host_and_service.enter(&current_executions.scope());
        
        // From each compromised host, find what other hosts can be reached
        let reachable_destinations = current_executions
            .map(|execution| (execution.compromised_host.clone(), execution.attacker_id.clone()))
            .join(&access_in_scope)
            .map(|(_source_host, (attacker_id, (destination_host, service_name)))| {
                ((destination_host, service_name), attacker_id)
            });
        
        // Join with vulnerabilities to get new code executions
        let newly_discovered_executions = reachable_destinations
            .join(&vulns_in_scope)
            .map(|((host, _service), (attacker_id, privilege))| AttackerCodeExecution {
                attacker_id,
                compromised_host: host,
                obtained_privilege: privilege,
            });
        
        // Combine new executions with existing ones and remove duplicates
        newly_discovered_executions
            .concat(current_executions)
            .distinct()
    });

    // Step 4: Attacker owns machine if they have root privilege
    // ownsMachine(attacker, host) :- execCode(attacker, host, root)
    
    let machines_owned_by_attackers = all_code_executions
        .filter(|execution| execution.obtained_privilege == PrivilegeLevel::Root)
        .map(|execution| AttackerOwnsMachine {
            attacker_id: execution.attacker_id,
            owned_host: execution.compromised_host,
        })
        .distinct();

    // Step 5: Check if attacker reached their goal
    // goalReached(attacker, target) :- attackerGoal(attacker, target), ownsMachine(attacker, target)
    
    // Get keys of owned machines for semijoin
    let owned_machine_keys = machines_owned_by_attackers
        .map(|owned| (owned.attacker_id.clone(), owned.owned_host.clone()))
        .distinct();
    
    // Index goals by (attacker, target)
    let goals_with_key = attacker_goals_collection
        .map(|goal| ((goal.attacker_id.clone(), goal.target_host_name.clone()), goal));
    
    // Join goals with owned machines
    let successfully_reached_goals = goals_with_key
        .semijoin(&owned_machine_keys)
        .map(|(_, goal)| AttackerGoalReached {
            attacker_id: goal.attacker_id,
            reached_target: goal.target_host_name,
        });

    // Consolidate results to merge duplicate updates
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
