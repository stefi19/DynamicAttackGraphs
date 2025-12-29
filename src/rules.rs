//! Attack Graph Rules Implementation
//!
//! This module translates MulVAL-style logical rules into differential dataflow
//! operators (map, filter, join, iterate).

use differential_dataflow::collection::Collection;
use differential_dataflow::operators::iterate::Iterate;
use differential_dataflow::operators::join::Join;
use differential_dataflow::operators::reduce::Threshold;
use differential_dataflow::operators::Consolidate;
use timely::dataflow::Scope;

use crate::schema::*;

/// Builds the complete attack graph dataflow.
///
/// # Arguments
/// * `vulnerabilities` - Collection of known vulnerabilities
/// * `network_access` - Collection of network connectivity facts
/// * `firewall_deny_rules` - Collection of firewall deny rules
/// * `attacker_locations` - Collection of initial attacker positions
/// * `attacker_goals` - Collection of attacker objectives
///
/// # Returns
/// A tuple of derived collections: (exec_code, owns_machine, goals_reached)
pub fn build_attack_graph<G>(
    vulnerabilities: &Collection<G, Vulnerability>,
    network_access: &Collection<G, NetworkAccess>,
    firewall_deny_rules: &Collection<G, FirewallRule>,
    attacker_locations: &Collection<G, AttackerLocation>,
    attacker_goals: &Collection<G, AttackerGoal>,
) -> (
    Collection<G, ExecCode>,
    Collection<G, OwnsMachine>,
    Collection<G, GoalReached>,
)
where
    G: Scope,
    G::Timestamp: differential_dataflow::lattice::Lattice + Ord,
{
    // ========================================================================
    // RULE 0: Compute effective network access
    // ========================================================================
    // effective_access(Src, Dst, Service) :-
    //     network_access(Src, Dst, Service),
    //     NOT firewall_deny(Src, Dst, Service).
    
    // Key the network access by (src, dst, service) for anti-join
    // antijoin expects Collection<G, K> not Collection<G, (K, V)>
    let network_keyed = network_access
        .map(|na| ((na.src_host.clone(), na.dst_host.clone(), na.service.clone()), na));
    
    // For antijoin, we need just the keys (not key-value pairs)
    let denied_keys = firewall_deny_rules
        .filter(|rule| rule.action == FirewallAction::Deny)
        .map(|rule| (rule.src.clone(), rule.dst.clone(), rule.service.clone()))
        .distinct();
    
    // Anti-join: keep network access that is NOT denied
    let effective_access = network_keyed
        .antijoin(&denied_keys)
        .map(|(_, na)| EffectiveAccess {
            src_host: na.src_host,
            dst_host: na.dst_host,
            service: na.service,
        });

    // ========================================================================
    // RULE 1: Initial code execution from attacker location
    // ========================================================================
    // execCode(Attacker, Host, Privilege) :-
    //     attackerLocated(Attacker, Host, Privilege).
    
    let initial_exec = attacker_locations
        .map(|loc| ExecCode {
            attacker: loc.attacker,
            host: loc.host,
            privilege: loc.privilege,
        });

    // ========================================================================
    // RULE 2 & 3: Transitive attack propagation (with iteration)
    // ========================================================================
    // execCode(Attacker, DstHost, NewPriv) :-
    //     execCode(Attacker, SrcHost, _),
    //     effectiveAccess(SrcHost, DstHost, Service),
    //     vulExists(DstHost, _, Service, NewPriv).
    //
    // This is a RECURSIVE rule - we need to iterate until fixpoint.
    
    // Prepare effective access keyed by source host
    let access_by_src = effective_access
        .map(|ea| (ea.src_host.clone(), (ea.dst_host.clone(), ea.service.clone())));
    
    // Prepare vulnerabilities keyed by (host, service)
    let vuln_by_host_service = vulnerabilities
        .map(|v| ((v.host.clone(), v.service.clone()), v.grants_privilege.clone()));

    // Use iterate for recursive attack propagation
    let exec_code = initial_exec.iterate(|inner_exec| {
        // Bring external collections into the iteration scope
        let access = access_by_src.enter(&inner_exec.scope());
        let vulns = vuln_by_host_service.enter(&inner_exec.scope());
        
        // From current execution position, find reachable hosts via network
        let can_reach = inner_exec
            .map(|ec| (ec.host.clone(), ec.attacker.clone()))
            .join(&access)
            .map(|(_src_host, (attacker, (dst_host, service)))| {
                ((dst_host, service), attacker)
            });
        
        // Join with vulnerabilities on (host, service) to get new execution
        let new_exec = can_reach
            .join(&vulns)
            .map(|((host, _service), (attacker, privilege))| ExecCode {
                attacker,
                host,
                privilege,
            });
        
        // Combine with existing and deduplicate
        new_exec
            .concat(inner_exec)
            .distinct()
    });

    // ========================================================================
    // RULE 4: Attacker owns machine if they have root privilege
    // ========================================================================
    // ownsMachine(Attacker, Host) :-
    //     execCode(Attacker, Host, root).
    
    let owns_machine = exec_code
        .filter(|ec| ec.privilege == Privilege::Root)
        .map(|ec| OwnsMachine {
            attacker: ec.attacker,
            host: ec.host,
        })
        .distinct();

    // ========================================================================
    // RULE 5: Goal reached when attacker owns target machine
    // ========================================================================
    // goalReached(Attacker, Target) :-
    //     attackerGoal(Attacker, Target),
    //     ownsMachine(Attacker, Target).
    
    // For semijoin, we need just the keys
    let owns_keys = owns_machine
        .map(|om| (om.attacker.clone(), om.host.clone()))
        .distinct();
    
    let goals_keyed = attacker_goals
        .map(|g| ((g.attacker.clone(), g.target_host.clone()), g));
    
    let goals_reached = goals_keyed
        .semijoin(&owns_keys)
        .map(|(_, goal)| GoalReached {
            attacker: goal.attacker,
            target: goal.target_host,
        });

    // Consolidate to merge duplicate diffs
    (
        exec_code.consolidate(),
        owns_machine.consolidate(),
        goals_reached.consolidate(),
    )
}

/// Alternative simpler implementation without full iteration
/// Uses a fixed number of hops for bounded attack depth
pub fn build_attack_graph_bounded<G>(
    vulnerabilities: &Collection<G, Vulnerability>,
    network_access: &Collection<G, NetworkAccess>,
    attacker_locations: &Collection<G, AttackerLocation>,
    attacker_goals: &Collection<G, AttackerGoal>,
    max_hops: usize,
) -> (
    Collection<G, ExecCode>,
    Collection<G, OwnsMachine>,
    Collection<G, GoalReached>,
)
where
    G: Scope,
    G::Timestamp: differential_dataflow::lattice::Lattice + Ord,
{
    // Initial execution positions
    let mut exec_code = attacker_locations
        .map(|loc| ExecCode {
            attacker: loc.attacker,
            host: loc.host,
            privilege: loc.privilege,
        });

    // Prepare collections for joining
    let access_by_src = network_access
        .map(|na| (na.src_host.clone(), (na.dst_host.clone(), na.service.clone())));
    
    let vuln_by_host_service = vulnerabilities
        .map(|v| ((v.host.clone(), v.service.clone()), v.grants_privilege.clone()));

    // Unroll the recursion for a fixed number of hops
    for _hop in 0..max_hops {
        let new_exec = exec_code
            .map(|ec| (ec.host.clone(), ec.attacker.clone()))
            .join(&access_by_src)
            .map(|(_src, (attacker, (dst, service)))| {
                ((dst, service), attacker)
            })
            .join(&vuln_by_host_service)
            .map(|((host, _service), (attacker, privilege))| ExecCode {
                attacker,
                host,
                privilege,
            });
        
        exec_code = exec_code.concat(&new_exec).distinct();
    }

    // Derive owns_machine
    let owns_machine = exec_code
        .filter(|ec| ec.privilege == Privilege::Root)
        .map(|ec| OwnsMachine {
            attacker: ec.attacker,
            host: ec.host,
        })
        .distinct();

    // Check goals - use semijoin with just keys
    let owns_keys = owns_machine
        .map(|om| (om.attacker.clone(), om.host.clone()))
        .distinct();
    
    let goals_keyed = attacker_goals
        .map(|g| ((g.attacker.clone(), g.target_host.clone()), g));
    
    let goals_reached = goals_keyed
        .semijoin(&owns_keys)
        .map(|(_, goal)| GoalReached {
            attacker: goal.attacker,
            target: goal.target_host,
        });

    (exec_code, owns_machine, goals_reached)
}
