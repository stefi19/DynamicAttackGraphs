use std::collections::HashSet;

use crate::schema::{
    AttackerCodeExecution, AttackerGoalReached, AttackerOwnsMachine, AttackerStartingPosition,
    AttackerTargetGoal, EffectiveNetworkAccess, FirewallRuleAction, FirewallRuleRecord,
    NetworkAccessRule, PrivilegeLevel, VulnerabilityRecord,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NaiveAttackGraph {
    pub effective_network_access: HashSet<EffectiveNetworkAccess>,
    pub code_executions: HashSet<AttackerCodeExecution>,
    pub machines_owned: HashSet<AttackerOwnsMachine>,
    pub goals_reached: HashSet<AttackerGoalReached>,
}

/// Computes the attack graph from scratch using a direct HashSet fixpoint.
///
/// This evaluator intentionally mirrors the logical rules in `rules.rs`
/// without using Differential Dataflow. It is meant as a small-graph
/// correctness oracle, not as a performance baseline.
pub fn evaluate_attack_graph_naive(
    vulnerabilities: Vec<VulnerabilityRecord>,
    network_access: Vec<NetworkAccessRule>,
    firewall_rules: Vec<FirewallRuleRecord>,
    attacker_positions: Vec<AttackerStartingPosition>,
    attacker_goals: Vec<AttackerTargetGoal>,
) -> NaiveAttackGraph {
    let denied_routes: HashSet<_> = firewall_rules
        .iter()
        .filter(|rule| rule.rule_action == FirewallRuleAction::Deny)
        .map(|rule| {
            (
                rule.source_zone.clone(),
                rule.destination_host.clone(),
                rule.service_name.clone(),
            )
        })
        .collect();

    let effective_network_access: HashSet<_> = network_access
        .into_iter()
        .filter(|access| {
            !denied_routes.contains(&(
                access.source_host.clone(),
                access.destination_host.clone(),
                access.service_name.clone(),
            ))
        })
        .map(|access| EffectiveNetworkAccess {
            source_host: access.source_host,
            destination_host: access.destination_host,
            service_name: access.service_name,
        })
        .collect();

    let mut code_executions: HashSet<_> = attacker_positions
        .into_iter()
        .map(|position| AttackerCodeExecution {
            attacker_id: position.attacker_id,
            compromised_host: position.starting_host,
            obtained_privilege: position.initial_privilege,
        })
        .collect();

    loop {
        let mut changed = false;
        let known_executions: Vec<_> = code_executions.iter().cloned().collect();

        for execution in &known_executions {
            for access in effective_network_access
                .iter()
                .filter(|access| access.source_host == execution.compromised_host)
            {
                for vulnerability in vulnerabilities.iter().filter(|vulnerability| {
                    vulnerability.host_name == access.destination_host
                        && vulnerability.affected_service == access.service_name
                }) {
                    let derived = AttackerCodeExecution {
                        attacker_id: execution.attacker_id.clone(),
                        compromised_host: access.destination_host.clone(),
                        obtained_privilege: vulnerability.privilege_gained_on_exploit.clone(),
                    };

                    changed |= code_executions.insert(derived);
                }
            }
        }

        if !changed {
            break;
        }
    }

    let machines_owned: HashSet<_> = code_executions
        .iter()
        .filter(|execution| execution.obtained_privilege == PrivilegeLevel::Root)
        .map(|execution| AttackerOwnsMachine {
            attacker_id: execution.attacker_id.clone(),
            owned_host: execution.compromised_host.clone(),
        })
        .collect();

    let owned_keys: HashSet<_> = machines_owned
        .iter()
        .map(|owned| (owned.attacker_id.clone(), owned.owned_host.clone()))
        .collect();

    let goals_reached: HashSet<_> = attacker_goals
        .into_iter()
        .filter(|goal| {
            owned_keys.contains(&(goal.attacker_id.clone(), goal.target_host_name.clone()))
        })
        .map(|goal| AttackerGoalReached {
            attacker_id: goal.attacker_id,
            reached_target: goal.target_host_name,
        })
        .collect();

    NaiveAttackGraph {
        effective_network_access,
        code_executions,
        machines_owned,
        goals_reached,
    }
}
