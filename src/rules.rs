// Attack graph rules implementation
// ----------------------------------
// This module implements the core logic that translates MulVAL-style
// Datalog rules into differential-dataflow operators.  The overall
// design decomposes the computation into strata (a common technique
// when there is negation):
//
//  - Stratum 0: Base facts (vulnerabilities, network rules, firewall)
//  - Stratum 1: Effective network access (network edges minus denies)
//  - Stratum 2: Recursive reachability (execCode) implemented with
//    differential-dataflow's `iterate()` to compute a fixed point
//  - Stratum 3: Ownership and goals derived from execCode
//
// The code is intentionally explicit: it creates keyed collections
// for joins, explains `enter()` for the iterative scope, and uses
// `.distinct()` to ensure convergence of the fixed-point computation.

use differential_dataflow::collection::Collection;
use differential_dataflow::operators::iterate::Iterate;
use differential_dataflow::operators::Join;
use differential_dataflow::operators::Threshold;
use timely::dataflow::Scope;

use crate::schema::*;

// ----------------------------------------------------------------
// build_attack_graph
// ----------------------------------------------------------------
// Public function that wires the dataflow for attack graph
// derivation.  It accepts several `Collection<G, T>` inputs (the raw
// facts) and returns derived collections.  The generic parameter `G`
// is the timely/differential scope (worker-local execution context).
// The timestamp bound (`G::Timestamp: Lattice + Ord`) is required by
// differential-dataflow for iterative computations.
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
    build_attack_graph_internal(
        vulnerability_collection,
        None,
        network_access_collection,
        firewall_rules_collection,
        attacker_positions_collection,
        attacker_goals_collection,
    )
}

/// Builds an attack graph with both remote service vulnerabilities and
/// local privilege escalation vulnerabilities.
pub fn build_attack_graph_with_local_vulnerabilities<G>(
    vulnerability_collection: &Collection<G, VulnerabilityRecord>,
    local_vulnerability_collection: &Collection<G, LocalVulnerabilityRecord>,
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
    build_attack_graph_internal(
        vulnerability_collection,
        Some(local_vulnerability_collection),
        network_access_collection,
        firewall_rules_collection,
        attacker_positions_collection,
        attacker_goals_collection,
    )
}

fn build_attack_graph_internal<G>(
    vulnerability_collection: &Collection<G, VulnerabilityRecord>,
    local_vulnerability_collection: Option<&Collection<G, LocalVulnerabilityRecord>>,
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
    // STRATUM 1: Effective network access (network edges minus denies)
    // =========================================================================
    // We implement: effectiveAccess(S,D,Svc) :- network(S,D,Svc), NOT deny(S,D,Svc).
    // Implementation steps:
    //  1. Key the network edges by (src,dst,svc) so joins/antijoins are keyed.
    //  2. Extract the set of deny keys from firewall rules (filter by Deny).
    //  3. Antijoin the network set with the deny set to remove blocked edges.

    // 1) key network rules by (src, dst, service)
    let network_access_keyed_by_route = network_access_collection.map(|rule| {
        // Create an explicit route key tuple for joining/antijoins.
        let route_key = (
            rule.source_host.clone(),
            rule.destination_host.clone(),
            rule.service_name.clone(),
        );
        (route_key, rule)
    });

    // 2) extract deny keys from firewall rules
    let blocked_route_keys = firewall_rules_collection
        // Keep only explicit Deny rules; Allow rules are not used for
        // negation here because the default behaviour is that the
        // network rule permits unless denied.
        .filter(|rule| rule.rule_action == FirewallRuleAction::Deny)
        // Map to the same key shape as the network rules
        .map(|rule| {
            (
                rule.source_zone.clone(),
                rule.destination_host.clone(),
                rule.service_name.clone(),
            )
        })
        // distinct() removes duplicates and reduces work for the antijoin
        .distinct();

    // 3) antijoin: keep network edges that are NOT present in blocked_route_keys
    let effective_network_access = network_access_keyed_by_route
        .antijoin(&blocked_route_keys)
        // Restore the original structure but now only for effective edges
        .map(|(_, original_rule)| EffectiveNetworkAccess {
            source_host: original_rule.source_host,
            destination_host: original_rule.destination_host,
            service_name: original_rule.service_name,
        });

    // =========================================================================
    // STRATUM 2: Recursive computation of execCode (reachability + exploitation)
    // =========================================================================
    // High-level rules implemented:
    //   execCode(A,H,P) :- attackerLocation(A,H,P).
    //   execCode(A,D,P) :- execCode(A,Src,_), effectiveAccess(Src,D,Svc), vulnerability(D,_,Svc,P).
    // We implement this using `iterate()` which repeatedly applies the
    // body until no new facts are produced (fixed point).  Inside the
    // iterate scope we must `enter()` static collections so they are
    // visible in the inner scope.

    // Base case: where the attacker starts
    let initial_code_execution =
        attacker_positions_collection.map(|position| AttackerCodeExecution {
            attacker_id: position.attacker_id,
            compromised_host: position.starting_host,
            obtained_privilege: position.initial_privilege,
        });

    // Index effective access by source host to accelerate joins
    let access_indexed_by_source = effective_network_access.map(|access| {
        (
            access.source_host.clone(),
            (access.destination_host.clone(), access.service_name.clone()),
        )
    });

    // Index vulnerabilities by (host, service) for efficient lookup
    let vulnerabilities_indexed_by_host_service = vulnerability_collection.map(|vuln| {
        (
            (vuln.host_name.clone(), vuln.affected_service.clone()),
            vuln.privilege_gained_on_exploit.clone(),
        )
    });

    // Index local privilege escalation vulnerabilities by host. These
    // do not require network movement; they upgrade an existing
    // non-root execCode fact on the same host.
    let local_vulnerabilities_indexed_by_host = local_vulnerability_collection.map(|collection| {
        collection.map(|vuln| {
            (
                vuln.host_name.clone(),
                vuln.privilege_gained_on_exploit.clone(),
            )
        })
    });

    // Now run the fixed-point iteration.  `iterate()` provides the
    // inner collection `current_executions`, representing the set of
    // execCode facts discovered so far.  Each iteration expands the
    // frontier by one hop through effective network access and
    // exploits.
    let all_code_executions = initial_code_execution.iterate(|current_executions| {
        // `enter()` moves a collection from the outer scope into the
        // inner iterative scope. This is necessary because
        // `access_indexed_by_source` and `vulnerabilities_indexed_by_host_service`
        // are created outside the iterate scope.
        let access_in_scope = access_indexed_by_source.enter(&current_executions.scope());
        let vulns_in_scope =
            vulnerabilities_indexed_by_host_service.enter(&current_executions.scope());
        let local_vulns_in_scope = local_vulnerabilities_indexed_by_host
            .as_ref()
            .map(|collection| collection.enter(&current_executions.scope()));

        // Step A: For every execCode(attacker, src, _), find reachable
        // destinations (dst, service) using the indexed access table.
        // The result shape is ((dst, service), attacker)
        let reachable_destinations = current_executions
            .map(|exec| (exec.compromised_host.clone(), exec.attacker_id.clone()))
            // join on source host -> yields (src, ((attacker),(dst,service)))
            .join(&access_in_scope)
            .map(|(_source, (attacker_id, (destination, service)))| {
                // Re-key by (destination, service) so we can check for a vuln
                ((destination, service), attacker_id)
            });

        // Step B: For each reachable (dst, service) check if dst has a
        // vulnerability on that service and produce a new execCode fact
        // with the privilege obtained from the vulnerability.
        let newly_compromised_hosts = reachable_destinations.join(&vulns_in_scope).map(
            |((host, _service), (attacker_id, privilege))| AttackerCodeExecution {
                attacker_id,
                compromised_host: host,
                obtained_privilege: privilege,
            },
        );

        let locally_escalated_executions = match local_vulns_in_scope {
            Some(local_vulns) => current_executions
                .filter(|exec| exec.obtained_privilege != PrivilegeLevel::Root)
                .map(|exec| (exec.compromised_host.clone(), exec.attacker_id.clone()))
                .join(&local_vulns)
                .map(|(host, (attacker_id, privilege))| AttackerCodeExecution {
                    attacker_id,
                    compromised_host: host,
                    obtained_privilege: privilege,
                }),
            None => current_executions.filter(|_| false),
        };

        // Step C: combine newly discovered compromises with the
        // previously discovered set and deduplicate with `distinct()`.
        // The `distinct()` call is crucial: it ensures that once a
        // fact has been produced, it does not reappear in subsequent
        // iterations. This guarantees that the fixed point computation
        // will terminate even in presence of cycles.
        newly_compromised_hosts
            .concat(&locally_escalated_executions)
            .concat(current_executions)
            .distinct()
    });

    // =========================================================================
    // STRATUM 3: Ownership and goal checking
    // =========================================================================
    // A machine is considered "owned" by an attacker if the attacker
    // achieves Root privilege on it.  Goals are checked by semijoining
    // the goal list with the owned machines.

    // Machines where an attacker obtained Root privilege
    let machines_owned_by_attackers = all_code_executions
        .filter(|exec| exec.obtained_privilege == PrivilegeLevel::Root)
        .map(|exec| AttackerOwnsMachine {
            attacker_id: exec.attacker_id,
            owned_host: exec.compromised_host,
        })
        .distinct();

    // Key owned machines by (attacker, host) for semijoin
    let owned_machine_keys = machines_owned_by_attackers
        .map(|owned| (owned.attacker_id.clone(), owned.owned_host.clone()))
        .distinct();

    // Index goals by (attacker, target)
    let goals_keyed = attacker_goals_collection.map(|goal| {
        (
            (goal.attacker_id.clone(), goal.target_host_name.clone()),
            goal,
        )
    });

    // Semijoin goals with owned machines to produce reached goals
    let successfully_reached_goals =
        goals_keyed
            .semijoin(&owned_machine_keys)
            .map(|(_, goal)| AttackerGoalReached {
                attacker_id: goal.attacker_id,
                reached_target: goal.target_host_name,
            });

    // Consolidate the outputs: this merges multiple diff updates for
    // the same value into a single diff and reduces noise for the
    // consumers of the returned collections.
    (
        all_code_executions.consolidate(),
        machines_owned_by_attackers.consolidate(),
        successfully_reached_goals.consolidate(),
    )
}

// ----------------------------------------------------------------
// build_attack_graph_with_max_hops
// ----------------------------------------------------------------
// An alternative non-iterative implementation that expands the
// attacker's reach up to `maximum_attack_hops`.  This is useful for
// experiments where you want an explicit bound on attacker depth or
// when the underlying iterative engine is not desired.
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
    // Initialize with attacker starting positions
    let mut current_code_executions =
        attacker_positions_collection.map(|position| AttackerCodeExecution {
            attacker_id: position.attacker_id,
            compromised_host: position.starting_host,
            obtained_privilege: position.initial_privilege,
        });

    // Index network access and vulnerabilities similarly to above
    let network_access_by_source = network_access_collection.map(|access| {
        (
            access.source_host.clone(),
            (access.destination_host.clone(), access.service_name.clone()),
        )
    });

    let vulnerabilities_by_host_and_service = vulnerability_collection.map(|vuln| {
        (
            (vuln.host_name.clone(), vuln.affected_service.clone()),
            vuln.privilege_gained_on_exploit.clone(),
        )
    });

    // Iteratively expand the frontier up to the maximum hop count
    for _hop_number in 0..maximum_attack_hops {
        let new_executions_this_hop = current_code_executions
            .map(|execution| {
                (
                    execution.compromised_host.clone(),
                    execution.attacker_id.clone(),
                )
            })
            .join(&network_access_by_source)
            .map(|(_source, (attacker_id, (destination, service)))| {
                ((destination, service), attacker_id)
            })
            .join(&vulnerabilities_by_host_and_service)
            .map(
                |((host, _service), (attacker_id, privilege))| AttackerCodeExecution {
                    attacker_id,
                    compromised_host: host,
                    obtained_privilege: privilege,
                },
            );

        // Combine the newly discovered facts with the existing ones and
        // deduplicate to avoid re-propagating the same facts across
        // iterations of this loop.
        current_code_executions = current_code_executions
            .concat(&new_executions_this_hop)
            .distinct();
    }

    // Same ownership/goal extraction as in the iterative version
    let machines_owned = current_code_executions
        .filter(|execution| execution.obtained_privilege == PrivilegeLevel::Root)
        .map(|execution| AttackerOwnsMachine {
            attacker_id: execution.attacker_id,
            owned_host: execution.compromised_host,
        })
        .distinct();

    let owned_keys = machines_owned
        .map(|owned| (owned.attacker_id.clone(), owned.owned_host.clone()))
        .distinct();

    let goals_indexed = attacker_goals_collection.map(|goal| {
        (
            (goal.attacker_id.clone(), goal.target_host_name.clone()),
            goal,
        )
    });

    let goals_reached = goals_indexed
        .semijoin(&owned_keys)
        .map(|(_, goal)| AttackerGoalReached {
            attacker_id: goal.attacker_id,
            reached_target: goal.target_host_name,
        });

    (current_code_executions, machines_owned, goals_reached)
}
