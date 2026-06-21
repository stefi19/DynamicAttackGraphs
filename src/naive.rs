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

#[cfg(test)]
mod tests {
    use super::*;

    fn no_firewall_rules() -> Vec<FirewallRuleRecord> {
        Vec::new()
    }

    fn attacker_at(host: &str) -> Vec<AttackerStartingPosition> {
        vec![AttackerStartingPosition::new(
            "attacker",
            host,
            PrivilegeLevel::User,
        )]
    }

    fn goal(host: &str) -> Vec<AttackerTargetGoal> {
        vec![AttackerTargetGoal::new("attacker", host)]
    }

    fn root_vulnerability(host: &str, cve: &str, service: &str) -> VulnerabilityRecord {
        VulnerabilityRecord::new(host, cve, service, PrivilegeLevel::Root)
    }

    fn exec_on(host: &str, privilege: PrivilegeLevel) -> AttackerCodeExecution {
        AttackerCodeExecution {
            attacker_id: "attacker".to_string(),
            compromised_host: host.to_string(),
            obtained_privilege: privilege,
        }
    }

    fn owns(host: &str) -> AttackerOwnsMachine {
        AttackerOwnsMachine {
            attacker_id: "attacker".to_string(),
            owned_host: host.to_string(),
        }
    }

    fn reached(host: &str) -> AttackerGoalReached {
        AttackerGoalReached {
            attacker_id: "attacker".to_string(),
            reached_target: host.to_string(),
        }
    }

    #[test]
    fn simple_one_hop_compromise_reaches_goal() {
        let graph = evaluate_attack_graph_naive(
            vec![root_vulnerability("web", "CVE-WEB", "https")],
            vec![NetworkAccessRule::new("internet", "web", "https")],
            no_firewall_rules(),
            attacker_at("internet"),
            goal("web"),
        );

        assert!(graph
            .effective_network_access
            .contains(&EffectiveNetworkAccess {
                source_host: "internet".to_string(),
                destination_host: "web".to_string(),
                service_name: "https".to_string(),
            }));
        assert!(graph
            .code_executions
            .contains(&exec_on("internet", PrivilegeLevel::User)));
        assert!(graph
            .code_executions
            .contains(&exec_on("web", PrivilegeLevel::Root)));
        assert!(graph.machines_owned.contains(&owns("web")));
        assert!(graph.goals_reached.contains(&reached("web")));
    }

    #[test]
    fn two_hop_compromise_propagates_to_database() {
        let graph = evaluate_attack_graph_naive(
            vec![
                VulnerabilityRecord::new("web", "CVE-WEB", "https", PrivilegeLevel::User),
                root_vulnerability("db", "CVE-DB", "postgres"),
            ],
            vec![
                NetworkAccessRule::new("internet", "web", "https"),
                NetworkAccessRule::new("web", "db", "postgres"),
            ],
            no_firewall_rules(),
            attacker_at("internet"),
            goal("db"),
        );

        assert!(graph
            .code_executions
            .contains(&exec_on("web", PrivilegeLevel::User)));
        assert!(graph
            .code_executions
            .contains(&exec_on("db", PrivilegeLevel::Root)));
        assert!(graph.machines_owned.contains(&owns("db")));
        assert!(graph.goals_reached.contains(&reached("db")));
    }

    #[test]
    fn firewall_deny_blocks_path() {
        let graph = evaluate_attack_graph_naive(
            vec![root_vulnerability("web", "CVE-WEB", "https")],
            vec![NetworkAccessRule::new("internet", "web", "https")],
            vec![FirewallRuleRecord::create_deny_rule(
                "internet", "web", "https",
            )],
            attacker_at("internet"),
            goal("web"),
        );

        assert!(graph.effective_network_access.is_empty());
        assert!(graph
            .code_executions
            .contains(&exec_on("internet", PrivilegeLevel::User)));
        assert!(!graph
            .code_executions
            .contains(&exec_on("web", PrivilegeLevel::Root)));
        assert!(!graph.machines_owned.contains(&owns("web")));
        assert!(!graph.goals_reached.contains(&reached("web")));
    }

    #[test]
    fn removing_vulnerability_changes_recomputed_result() {
        let network = vec![NetworkAccessRule::new("internet", "web", "https")];
        let initial_graph = evaluate_attack_graph_naive(
            vec![root_vulnerability("web", "CVE-WEB", "https")],
            network.clone(),
            no_firewall_rules(),
            attacker_at("internet"),
            goal("web"),
        );
        let patched_graph = evaluate_attack_graph_naive(
            Vec::new(),
            network,
            no_firewall_rules(),
            attacker_at("internet"),
            goal("web"),
        );

        assert!(initial_graph
            .code_executions
            .contains(&exec_on("web", PrivilegeLevel::Root)));
        assert!(initial_graph.goals_reached.contains(&reached("web")));
        assert!(!patched_graph
            .code_executions
            .contains(&exec_on("web", PrivilegeLevel::Root)));
        assert!(!patched_graph.goals_reached.contains(&reached("web")));
    }
}
