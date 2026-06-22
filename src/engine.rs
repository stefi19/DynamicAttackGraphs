use std::collections::{BTreeSet, HashSet};

use crate::naive::evaluate_attack_graph_naive_with_local_vulnerabilities;
use crate::schema::{
    AttackerCodeExecution, AttackerGoalReached, AttackerOwnsMachine, AttackerStartingPosition,
    AttackerTargetGoal, EffectiveNetworkAccess, FirewallRuleAction, FirewallRuleRecord,
    LocalVulnerabilityRecord, NetworkAccessRule, VulnerabilityRecord,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaseFacts {
    pub vulnerabilities: Vec<VulnerabilityRecord>,
    pub local_vulnerabilities: Vec<LocalVulnerabilityRecord>,
    pub network_access: Vec<NetworkAccessRule>,
    pub firewall_rules: Vec<FirewallRuleRecord>,
    pub attacker_positions: Vec<AttackerStartingPosition>,
    pub attacker_goals: Vec<AttackerTargetGoal>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DerivedFacts {
    pub effective_network_access: HashSet<EffectiveNetworkAccess>,
    pub code_executions: HashSet<AttackerCodeExecution>,
    pub machines_owned: HashSet<AttackerOwnsMachine>,
    pub goals_reached: HashSet<AttackerGoalReached>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactUpdate {
    InsertVulnerability(VulnerabilityRecord),
    RemoveVulnerability(VulnerabilityRecord),
    InsertLocalVulnerability(LocalVulnerabilityRecord),
    RemoveLocalVulnerability(LocalVulnerabilityRecord),
    InsertNetworkAccess(NetworkAccessRule),
    RemoveNetworkAccess(NetworkAccessRule),
    InsertFirewallDeny(FirewallRuleRecord),
    RemoveFirewallDeny(FirewallRuleRecord),
    InsertAttackerPosition(AttackerStartingPosition),
    RemoveAttackerPosition(AttackerStartingPosition),
    InsertGoal(AttackerTargetGoal),
    RemoveGoal(AttackerTargetGoal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRunResult {
    pub engine_name: &'static str,
    pub derived_facts: DerivedFacts,
}

pub trait AttackGraphEngine {
    fn name(&self) -> &'static str;
    fn load_snapshot(&mut self, facts: BaseFacts);
    fn apply_update(&mut self, update: FactUpdate);
    fn current_derived_facts(&self) -> DerivedFacts;

    fn apply_updates(&mut self, updates: &[FactUpdate]) {
        for update in updates {
            self.apply_update(update.clone());
        }
    }
}

impl BaseFacts {
    pub fn apply_update(&mut self, update: FactUpdate) {
        match update {
            FactUpdate::InsertVulnerability(fact) => self.vulnerabilities.push(fact),
            FactUpdate::RemoveVulnerability(fact) => {
                remove_one(&mut self.vulnerabilities, &fact);
            }
            FactUpdate::InsertLocalVulnerability(fact) => self.local_vulnerabilities.push(fact),
            FactUpdate::RemoveLocalVulnerability(fact) => {
                remove_one(&mut self.local_vulnerabilities, &fact);
            }
            FactUpdate::InsertNetworkAccess(fact) => self.network_access.push(fact),
            FactUpdate::RemoveNetworkAccess(fact) => {
                remove_one(&mut self.network_access, &fact);
            }
            FactUpdate::InsertFirewallDeny(mut fact) => {
                fact.rule_action = FirewallRuleAction::Deny;
                self.firewall_rules.push(fact);
            }
            FactUpdate::RemoveFirewallDeny(fact) => {
                remove_one(&mut self.firewall_rules, &fact);
            }
            FactUpdate::InsertAttackerPosition(fact) => self.attacker_positions.push(fact),
            FactUpdate::RemoveAttackerPosition(fact) => {
                remove_one(&mut self.attacker_positions, &fact);
            }
            FactUpdate::InsertGoal(fact) => self.attacker_goals.push(fact),
            FactUpdate::RemoveGoal(fact) => {
                remove_one(&mut self.attacker_goals, &fact);
            }
        }
    }

    pub fn apply_updates(&mut self, updates: &[FactUpdate]) {
        for update in updates {
            self.apply_update(update.clone());
        }
    }
}

pub fn evaluate_base_facts(facts: &BaseFacts) -> DerivedFacts {
    let graph = evaluate_attack_graph_naive_with_local_vulnerabilities(
        facts.vulnerabilities.clone(),
        facts.local_vulnerabilities.clone(),
        facts.network_access.clone(),
        facts.firewall_rules.clone(),
        facts.attacker_positions.clone(),
        facts.attacker_goals.clone(),
    );

    DerivedFacts {
        effective_network_access: graph.effective_network_access,
        code_executions: graph.code_executions,
        machines_owned: graph.machines_owned,
        goals_reached: graph.goals_reached,
    }
}

pub fn effective_network_access_from_base(facts: &BaseFacts) -> HashSet<EffectiveNetworkAccess> {
    let denied_routes: HashSet<_> = facts
        .firewall_rules
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

    facts
        .network_access
        .iter()
        .filter(|access| {
            !denied_routes.contains(&(
                access.source_host.clone(),
                access.destination_host.clone(),
                access.service_name.clone(),
            ))
        })
        .map(|access| EffectiveNetworkAccess {
            source_host: access.source_host.clone(),
            destination_host: access.destination_host.clone(),
            service_name: access.service_name.clone(),
        })
        .collect()
}

pub fn compare_derived_facts(left: &DerivedFacts, right: &DerivedFacts) -> Result<(), String> {
    let mut differences = Vec::new();

    compare_sets(
        "effective_network_access",
        &left.effective_network_access,
        &right.effective_network_access,
        &mut differences,
    );
    compare_sets(
        "code_executions",
        &left.code_executions,
        &right.code_executions,
        &mut differences,
    );
    compare_sets(
        "machines_owned",
        &left.machines_owned,
        &right.machines_owned,
        &mut differences,
    );
    compare_sets(
        "goals_reached",
        &left.goals_reached,
        &right.goals_reached,
        &mut differences,
    );

    if differences.is_empty() {
        Ok(())
    } else {
        Err(differences.join("\n"))
    }
}

fn remove_one<T: PartialEq>(facts: &mut Vec<T>, fact: &T) {
    if let Some(index) = facts.iter().position(|candidate| candidate == fact) {
        facts.remove(index);
    }
}

fn compare_sets<T>(
    label: &str,
    left: &HashSet<T>,
    right: &HashSet<T>,
    differences: &mut Vec<String>,
) where
    T: Ord + Clone + std::fmt::Debug,
{
    let left_ordered: BTreeSet<_> = left.iter().cloned().collect();
    let right_ordered: BTreeSet<_> = right.iter().cloned().collect();
    let only_left: Vec<_> = left_ordered.difference(&right_ordered).take(5).collect();
    let only_right: Vec<_> = right_ordered.difference(&left_ordered).take(5).collect();

    if !only_left.is_empty() || !only_right.is_empty() {
        differences.push(format!(
            "{label} differs: left_count={}, right_count={}, only_left={only_left:?}, only_right={only_right:?}",
            left.len(),
            right.len()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::PrivilegeLevel;

    #[test]
    fn compare_derived_facts_accepts_equal_sets() {
        let mut left = DerivedFacts::default();
        left.code_executions.insert(AttackerCodeExecution {
            attacker_id: "eve".to_string(),
            compromised_host: "web".to_string(),
            obtained_privilege: PrivilegeLevel::User,
        });

        let right = left.clone();
        assert!(compare_derived_facts(&left, &right).is_ok());
    }

    #[test]
    fn compare_derived_facts_reports_differences() {
        let mut left = DerivedFacts::default();
        let right = DerivedFacts::default();
        left.goals_reached.insert(AttackerGoalReached {
            attacker_id: "eve".to_string(),
            reached_target: "admin".to_string(),
        });

        let error = compare_derived_facts(&left, &right).expect_err("sets should differ");
        assert!(error.contains("goals_reached differs"));
        assert!(error.contains("left_count=1"));
    }

    #[test]
    fn base_facts_apply_update_removes_one_matching_fact() {
        let vulnerability = VulnerabilityRecord::new("web", "CVE-1", "https", PrivilegeLevel::Root);
        let mut facts = BaseFacts {
            vulnerabilities: vec![vulnerability.clone(), vulnerability.clone()],
            ..BaseFacts::default()
        };

        facts.apply_update(FactUpdate::RemoveVulnerability(vulnerability));
        assert_eq!(facts.vulnerabilities.len(), 1);
    }
}
