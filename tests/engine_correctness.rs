use dynamic_attack_graphs::{
    compare_derived_facts, AttackGraphEngine, AttackerStartingPosition, AttackerTargetGoal,
    BaseFacts, DifferentialEngine, FactUpdate, FirewallRuleRecord, FullRecomputeEngine,
    LocalVulnerabilityRecord, NaiveEngine, NetworkAccessRule, PrivilegeLevel, VulnerabilityRecord,
};

fn chain_facts() -> BaseFacts {
    BaseFacts {
        vulnerabilities: vec![
            VulnerabilityRecord::new("web", "CVE-WEB", "https", PrivilegeLevel::User),
            VulnerabilityRecord::new("db", "CVE-DB", "postgres", PrivilegeLevel::Root),
        ],
        network_access: vec![
            NetworkAccessRule::new("internet", "web", "https"),
            NetworkAccessRule::new("web", "db", "postgres"),
        ],
        attacker_positions: vec![AttackerStartingPosition::new(
            "eve",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("eve", "db")],
        ..BaseFacts::default()
    }
}

fn assert_matches_recompute(facts: BaseFacts, updates: &[FactUpdate]) {
    let mut differential = DifferentialEngine::new();
    let mut recompute = FullRecomputeEngine::new();

    differential.load_snapshot(facts.clone());
    recompute.load_snapshot(facts);

    compare_derived_facts(
        &differential.current_derived_facts(),
        &recompute.current_derived_facts(),
    )
    .expect("initial differential output should match full recomputation");

    differential.apply_updates(updates);
    recompute.apply_updates(updates);

    compare_derived_facts(
        &differential.current_derived_facts(),
        &recompute.current_derived_facts(),
    )
    .expect("updated differential output should match full recomputation");
}

#[test]
fn differential_initial_output_matches_full_recompute() {
    assert_matches_recompute(chain_facts(), &[]);
}

#[test]
fn differential_after_vulnerability_patch_matches_full_recompute() {
    let patched = VulnerabilityRecord::new("web", "CVE-WEB", "https", PrivilegeLevel::User);
    assert_matches_recompute(chain_facts(), &[FactUpdate::RemoveVulnerability(patched)]);
}

#[test]
fn differential_after_firewall_deny_matches_full_recompute() {
    let deny = FirewallRuleRecord::create_deny_rule("internet", "web", "https");
    assert_matches_recompute(chain_facts(), &[FactUpdate::InsertFirewallDeny(deny)]);
}

#[test]
fn differential_after_new_cve_matches_full_recompute() {
    let mut facts = chain_facts();
    facts.vulnerabilities.clear();
    let new_cve = VulnerabilityRecord::new("web", "CVE-WEB", "https", PrivilegeLevel::User);

    assert_matches_recompute(facts, &[FactUpdate::InsertVulnerability(new_cve)]);
}

#[test]
fn differential_with_local_privilege_escalation_matches_full_recompute() {
    let facts = BaseFacts {
        vulnerabilities: vec![VulnerabilityRecord::new(
            "web",
            "CVE-WEB",
            "https",
            PrivilegeLevel::User,
        )],
        local_vulnerabilities: vec![LocalVulnerabilityRecord::new(
            "web",
            "CVE-LOCAL",
            PrivilegeLevel::Root,
        )],
        network_access: vec![NetworkAccessRule::new("internet", "web", "https")],
        attacker_positions: vec![AttackerStartingPosition::new(
            "eve",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("eve", "web")],
        ..BaseFacts::default()
    };

    assert_matches_recompute(facts, &[]);
}

#[test]
fn naive_engine_matches_full_recompute_on_small_chain() {
    let facts = chain_facts();
    let mut naive = NaiveEngine::new();
    let mut recompute = FullRecomputeEngine::new();

    naive.load_snapshot(facts.clone());
    recompute.load_snapshot(facts);

    compare_derived_facts(
        &naive.current_derived_facts(),
        &recompute.current_derived_facts(),
    )
    .expect("naive engine should match full recomputation");
}
