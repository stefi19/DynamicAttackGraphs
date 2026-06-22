use std::collections::HashSet;

use crate::engine::DerivedFacts;
use crate::schema::HostIdentifier;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateMetrics {
    pub changed_base_facts: usize,
    pub changed_exec_code_facts: usize,
    pub changed_ownership_facts: usize,
    pub changed_goal_facts: usize,
    pub changed_derived_facts: usize,
    pub affected_hosts: usize,
    pub affected_region_depth_estimate: Option<usize>,
}

pub fn diff_derived_facts(before: &DerivedFacts, after: &DerivedFacts) -> UpdateMetrics {
    let changed_exec_code_facts =
        symmetric_difference_count(&before.code_executions, &after.code_executions);
    let changed_ownership_facts =
        symmetric_difference_count(&before.machines_owned, &after.machines_owned);
    let changed_goal_facts =
        symmetric_difference_count(&before.goals_reached, &after.goals_reached);
    let changed_effective_access = symmetric_difference_count(
        &before.effective_network_access,
        &after.effective_network_access,
    );

    let changed_derived_facts = changed_effective_access
        + changed_exec_code_facts
        + changed_ownership_facts
        + changed_goal_facts;
    let affected_hosts = affected_hosts_from_diff(before, after).len();

    UpdateMetrics {
        changed_base_facts: 0,
        changed_exec_code_facts,
        changed_ownership_facts,
        changed_goal_facts,
        changed_derived_facts,
        affected_hosts,
        affected_region_depth_estimate: None,
    }
}

pub fn affected_hosts_from_diff(
    before: &DerivedFacts,
    after: &DerivedFacts,
) -> HashSet<HostIdentifier> {
    let mut hosts = HashSet::new();

    for fact in before
        .code_executions
        .symmetric_difference(&after.code_executions)
    {
        hosts.insert(fact.compromised_host.clone());
    }
    for fact in before
        .machines_owned
        .symmetric_difference(&after.machines_owned)
    {
        hosts.insert(fact.owned_host.clone());
    }
    for fact in before
        .goals_reached
        .symmetric_difference(&after.goals_reached)
    {
        hosts.insert(fact.reached_target.clone());
    }
    for fact in before
        .effective_network_access
        .symmetric_difference(&after.effective_network_access)
    {
        hosts.insert(fact.source_host.clone());
        hosts.insert(fact.destination_host.clone());
    }

    hosts
}

fn symmetric_difference_count<T>(before: &HashSet<T>, after: &HashSet<T>) -> usize
where
    T: Eq + std::hash::Hash,
{
    before.symmetric_difference(after).count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{evaluate_base_facts, BaseFacts, FactUpdate};
    use crate::schema::{
        AttackerStartingPosition, AttackerTargetGoal, NetworkAccessRule, PrivilegeLevel,
        VulnerabilityRecord,
    };

    #[test]
    fn no_change_gives_zero_changed_facts() {
        let facts = BaseFacts::default();
        let before = evaluate_base_facts(&facts);
        let after = evaluate_base_facts(&facts);

        let metrics = diff_derived_facts(&before, &after);
        assert_eq!(metrics.changed_derived_facts, 0);
        assert_eq!(metrics.affected_hosts, 0);
    }

    #[test]
    fn single_leaf_patch_changes_small_region() {
        let vulnerability =
            VulnerabilityRecord::new("leaf", "CVE-LEAF", "https", PrivilegeLevel::Root);
        let mut facts = BaseFacts {
            vulnerabilities: vec![vulnerability.clone()],
            network_access: vec![NetworkAccessRule::new("hub", "leaf", "https")],
            attacker_positions: vec![AttackerStartingPosition::new(
                "eve",
                "hub",
                PrivilegeLevel::User,
            )],
            attacker_goals: vec![AttackerTargetGoal::new("eve", "leaf")],
            ..BaseFacts::default()
        };
        let before = evaluate_base_facts(&facts);
        facts.apply_update(FactUpdate::RemoveVulnerability(vulnerability));
        let after = evaluate_base_facts(&facts);

        let metrics = diff_derived_facts(&before, &after);
        assert!(metrics.changed_exec_code_facts >= 1);
        assert_eq!(metrics.affected_hosts, 1);
    }

    #[test]
    fn early_chain_patch_changes_many_downstream_facts() {
        let first = VulnerabilityRecord::new("node_1", "CVE-1", "https", PrivilegeLevel::User);
        let mut facts = BaseFacts {
            vulnerabilities: vec![
                first.clone(),
                VulnerabilityRecord::new("node_2", "CVE-2", "https", PrivilegeLevel::User),
                VulnerabilityRecord::new("node_3", "CVE-3", "https", PrivilegeLevel::Root),
            ],
            network_access: vec![
                NetworkAccessRule::new("node_0", "node_1", "https"),
                NetworkAccessRule::new("node_1", "node_2", "https"),
                NetworkAccessRule::new("node_2", "node_3", "https"),
            ],
            attacker_positions: vec![AttackerStartingPosition::new(
                "eve",
                "node_0",
                PrivilegeLevel::User,
            )],
            attacker_goals: vec![AttackerTargetGoal::new("eve", "node_3")],
            ..BaseFacts::default()
        };

        let before = evaluate_base_facts(&facts);
        facts.apply_update(FactUpdate::RemoveVulnerability(first));
        let after = evaluate_base_facts(&facts);

        let metrics = diff_derived_facts(&before, &after);
        assert!(metrics.changed_exec_code_facts >= 3);
        assert!(metrics.affected_hosts >= 3);
    }
}
