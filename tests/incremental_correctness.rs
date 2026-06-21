use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use differential_dataflow::input::{Input, InputSession};
use dynamic_attack_graphs::{
    build_attack_graph, evaluate_attack_graph_naive, AttackerCodeExecution, AttackerGoalReached,
    AttackerOwnsMachine, AttackerStartingPosition, AttackerTargetGoal, FirewallRuleRecord,
    NetworkAccessRule, PrivilegeLevel, VulnerabilityRecord,
};
use timely::dataflow::operators::probe::Handle;

#[derive(Debug, Clone, Default)]
struct BaseFacts {
    vulnerabilities: Vec<VulnerabilityRecord>,
    network_access: Vec<NetworkAccessRule>,
    firewall_rules: Vec<FirewallRuleRecord>,
    attacker_positions: Vec<AttackerStartingPosition>,
    attacker_goals: Vec<AttackerTargetGoal>,
}

#[derive(Debug, Clone)]
enum FactUpdate {
    InsertVulnerability(VulnerabilityRecord),
    RemoveVulnerability(VulnerabilityRecord),
    InsertNetworkAccess(NetworkAccessRule),
    InsertFirewallRule(FirewallRuleRecord),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AttackGraphOutput {
    exec_code: BTreeMap<AttackerCodeExecution, isize>,
    owns_machine: BTreeMap<AttackerOwnsMachine, isize>,
    goals_reached: BTreeMap<AttackerGoalReached, isize>,
}

#[derive(Debug, Default)]
struct CapturedChanges {
    exec_code: Vec<(AttackerCodeExecution, usize, isize)>,
    owns_machine: Vec<(AttackerOwnsMachine, usize, isize)>,
    goals_reached: Vec<(AttackerGoalReached, usize, isize)>,
}

static TIMELY_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn collect_incremental_outputs(
    initial_facts: BaseFacts,
    updates: &[FactUpdate],
) -> (AttackGraphOutput, AttackGraphOutput) {
    let _runtime_guard = TIMELY_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("timely test runtime lock should not be poisoned");

    let updates = updates.to_vec();
    let captured = Arc::new(Mutex::new(CapturedChanges::default()));
    let captured_after_run = Arc::clone(&captured);

    timely::execute_directly(move |worker| {
        let mut probe = Handle::new();

        let captured_exec = Arc::clone(&captured);
        let captured_owns = Arc::clone(&captured);
        let captured_goals = Arc::clone(&captured);

        let (
            mut vulnerability_input,
            mut network_input,
            mut firewall_input,
            mut attacker_position_input,
            mut attacker_goal_input,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            let (vulnerability_handle, vulnerability_collection) =
                scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) =
                scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) =
                scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) =
                scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) =
                scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, owns_machine, goals_reached) = build_attack_graph(
                &vulnerability_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code
                .inspect(move |(record, time, diff)| {
                    captured_exec
                        .lock()
                        .expect("captured exec changes mutex should not be poisoned")
                        .exec_code
                        .push((record.clone(), *time, *diff));
                })
                .probe_with(&mut probe);

            owns_machine
                .inspect(move |(record, time, diff)| {
                    captured_owns
                        .lock()
                        .expect("captured ownership changes mutex should not be poisoned")
                        .owns_machine
                        .push((record.clone(), *time, *diff));
                })
                .probe_with(&mut probe);

            goals_reached
                .inspect(move |(record, time, diff)| {
                    captured_goals
                        .lock()
                        .expect("captured goal changes mutex should not be poisoned")
                        .goals_reached
                        .push((record.clone(), *time, *diff));
                })
                .probe_with(&mut probe);

            (
                vulnerability_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        insert_base_facts(
            &initial_facts,
            &mut vulnerability_input,
            &mut network_input,
            &mut firewall_input,
            &mut attacker_position_input,
            &mut attacker_goal_input,
        );
        advance_all_inputs(
            1,
            &mut vulnerability_input,
            &mut network_input,
            &mut firewall_input,
            &mut attacker_position_input,
            &mut attacker_goal_input,
        );

        while probe.less_than(&1) {
            worker.step();
        }

        apply_updates(
            &updates,
            &mut vulnerability_input,
            &mut network_input,
            &mut firewall_input,
        );
        advance_all_inputs(
            2,
            &mut vulnerability_input,
            &mut network_input,
            &mut firewall_input,
            &mut attacker_position_input,
            &mut attacker_goal_input,
        );

        while probe.less_than(&2) {
            worker.step();
        }
    });

    let changes = Arc::try_unwrap(captured_after_run)
        .expect("test should hold the only captured-change reference")
        .into_inner()
        .expect("captured changes mutex should not be poisoned");

    (
        output_at_logical_time(&changes, 1),
        output_at_logical_time(&changes, 2),
    )
}

fn collect_recomputed_outputs(facts: BaseFacts) -> AttackGraphOutput {
    let (_, final_output) = collect_incremental_outputs(facts, &[]);
    final_output
}

fn apply_updates_to_facts(facts: &mut BaseFacts, updates: &[FactUpdate]) {
    for update in updates {
        match update {
            FactUpdate::InsertVulnerability(vulnerability) => {
                facts.vulnerabilities.push(vulnerability.clone());
            }
            FactUpdate::RemoveVulnerability(vulnerability) => {
                facts.vulnerabilities.retain(|item| item != vulnerability);
            }
            FactUpdate::InsertNetworkAccess(access) => {
                facts.network_access.push(access.clone());
            }
            FactUpdate::InsertFirewallRule(rule) => {
                facts.firewall_rules.push(rule.clone());
            }
        }
    }
}

fn insert_base_facts(
    facts: &BaseFacts,
    vulnerability_input: &mut InputSession<usize, VulnerabilityRecord, isize>,
    network_input: &mut InputSession<usize, NetworkAccessRule, isize>,
    firewall_input: &mut InputSession<usize, FirewallRuleRecord, isize>,
    attacker_position_input: &mut InputSession<usize, AttackerStartingPosition, isize>,
    attacker_goal_input: &mut InputSession<usize, AttackerTargetGoal, isize>,
) {
    for vulnerability in &facts.vulnerabilities {
        vulnerability_input.insert(vulnerability.clone());
    }
    for access in &facts.network_access {
        network_input.insert(access.clone());
    }
    for rule in &facts.firewall_rules {
        firewall_input.insert(rule.clone());
    }
    for position in &facts.attacker_positions {
        attacker_position_input.insert(position.clone());
    }
    for goal in &facts.attacker_goals {
        attacker_goal_input.insert(goal.clone());
    }
}

fn apply_updates(
    updates: &[FactUpdate],
    vulnerability_input: &mut InputSession<usize, VulnerabilityRecord, isize>,
    network_input: &mut InputSession<usize, NetworkAccessRule, isize>,
    firewall_input: &mut InputSession<usize, FirewallRuleRecord, isize>,
) {
    for update in updates {
        match update {
            FactUpdate::InsertVulnerability(vulnerability) => {
                vulnerability_input.insert(vulnerability.clone());
            }
            FactUpdate::RemoveVulnerability(vulnerability) => {
                vulnerability_input.remove(vulnerability.clone());
            }
            FactUpdate::InsertNetworkAccess(access) => {
                network_input.insert(access.clone());
            }
            FactUpdate::InsertFirewallRule(rule) => {
                firewall_input.insert(rule.clone());
            }
        }
    }
}

fn advance_all_inputs(
    time: usize,
    vulnerability_input: &mut InputSession<usize, VulnerabilityRecord, isize>,
    network_input: &mut InputSession<usize, NetworkAccessRule, isize>,
    firewall_input: &mut InputSession<usize, FirewallRuleRecord, isize>,
    attacker_position_input: &mut InputSession<usize, AttackerStartingPosition, isize>,
    attacker_goal_input: &mut InputSession<usize, AttackerTargetGoal, isize>,
) {
    vulnerability_input.advance_to(time);
    network_input.advance_to(time);
    firewall_input.advance_to(time);
    attacker_position_input.advance_to(time);
    attacker_goal_input.advance_to(time);

    vulnerability_input.flush();
    network_input.flush();
    firewall_input.flush();
    attacker_position_input.flush();
    attacker_goal_input.flush();
}

fn output_at_logical_time(changes: &CapturedChanges, upper_time: usize) -> AttackGraphOutput {
    AttackGraphOutput {
        exec_code: active_facts_before(&changes.exec_code, upper_time),
        owns_machine: active_facts_before(&changes.owns_machine, upper_time),
        goals_reached: active_facts_before(&changes.goals_reached, upper_time),
    }
}

fn active_facts_before<T: Clone + Ord>(
    changes: &[(T, usize, isize)],
    upper_time: usize,
) -> BTreeMap<T, isize> {
    let mut active_facts = BTreeMap::new();

    for (record, time, diff) in changes {
        if *time < upper_time {
            *active_facts.entry(record.clone()).or_insert(0) += *diff;
        }
    }

    active_facts.retain(|_, diff| *diff != 0);
    active_facts
}

fn chain_base_facts() -> BaseFacts {
    BaseFacts {
        vulnerabilities: vec![
            VulnerabilityRecord::new("web", "CVE-WEB", "https", PrivilegeLevel::User),
            VulnerabilityRecord::new("db", "CVE-DB", "postgres", PrivilegeLevel::Root),
        ],
        network_access: vec![NetworkAccessRule::new("internet", "web", "https")],
        firewall_rules: Vec::new(),
        attacker_positions: vec![AttackerStartingPosition::new(
            "attacker",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("attacker", "db")],
    }
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

fn assert_incremental_update_matches_recompute(
    initial_facts: BaseFacts,
    updates: Vec<FactUpdate>,
) -> (AttackGraphOutput, AttackGraphOutput) {
    let (initial_output, incremental_after_update) =
        collect_incremental_outputs(initial_facts.clone(), &updates);
    let recomputed_initial = collect_recomputed_outputs(initial_facts.clone());

    let mut updated_facts = initial_facts;
    apply_updates_to_facts(&mut updated_facts, &updates);
    let recomputed_after_update = collect_recomputed_outputs(updated_facts);

    assert_eq!(initial_output, recomputed_initial);
    assert_eq!(incremental_after_update, recomputed_after_update);

    (initial_output, incremental_after_update)
}

fn assert_dataflow_matches_naive(facts: BaseFacts) {
    let dataflow_output = collect_recomputed_outputs(facts.clone());
    let naive_output = evaluate_attack_graph_naive(
        facts.vulnerabilities,
        facts.network_access,
        facts.firewall_rules,
        facts.attacker_positions,
        facts.attacker_goals,
    );

    assert_eq!(
        dataflow_output.exec_code,
        naive_output
            .code_executions
            .into_iter()
            .map(|fact| (fact, 1))
            .collect()
    );
    assert_eq!(
        dataflow_output.owns_machine,
        naive_output
            .machines_owned
            .into_iter()
            .map(|fact| (fact, 1))
            .collect()
    );
    assert_eq!(
        dataflow_output.goals_reached,
        naive_output
            .goals_reached
            .into_iter()
            .map(|fact| (fact, 1))
            .collect()
    );
}

#[test]
fn simple_chain_update_matches_recompute() {
    let facts = chain_base_facts();
    let (_initial_output, after_update) = assert_incremental_update_matches_recompute(
        facts,
        vec![FactUpdate::InsertNetworkAccess(NetworkAccessRule::new(
            "web", "db", "postgres",
        ))],
    );

    assert!(after_update
        .exec_code
        .contains_key(&exec_on("db", PrivilegeLevel::Root)));
    assert!(after_update.owns_machine.contains_key(&owns("db")));
    assert!(after_update.goals_reached.contains_key(&reached("db")));
}

#[test]
fn firewall_deny_update_matches_recompute() {
    let mut facts = chain_base_facts();
    facts
        .network_access
        .push(NetworkAccessRule::new("web", "db", "postgres"));

    let (initial_output, after_update) = assert_incremental_update_matches_recompute(
        facts,
        vec![FactUpdate::InsertFirewallRule(
            FirewallRuleRecord::create_deny_rule("internet", "web", "https"),
        )],
    );

    assert!(initial_output.goals_reached.contains_key(&reached("db")));
    assert!(!after_update
        .exec_code
        .contains_key(&exec_on("web", PrivilegeLevel::User)));
    assert!(!after_update.goals_reached.contains_key(&reached("db")));
}

#[test]
fn vulnerability_patch_update_matches_recompute() {
    let mut facts = chain_base_facts();
    facts
        .network_access
        .push(NetworkAccessRule::new("web", "db", "postgres"));

    let patched_vulnerability =
        VulnerabilityRecord::new("web", "CVE-WEB", "https", PrivilegeLevel::User);
    let (initial_output, after_update) = assert_incremental_update_matches_recompute(
        facts,
        vec![FactUpdate::RemoveVulnerability(patched_vulnerability)],
    );

    assert!(initial_output.goals_reached.contains_key(&reached("db")));
    assert!(!after_update
        .exec_code
        .contains_key(&exec_on("web", PrivilegeLevel::User)));
    assert!(!after_update.goals_reached.contains_key(&reached("db")));
}

#[test]
fn new_vulnerability_discovered_update_matches_recompute() {
    let facts = BaseFacts {
        vulnerabilities: vec![VulnerabilityRecord::new(
            "web",
            "CVE-WEB",
            "https",
            PrivilegeLevel::User,
        )],
        network_access: vec![
            NetworkAccessRule::new("internet", "web", "https"),
            NetworkAccessRule::new("web", "db", "postgres"),
        ],
        firewall_rules: Vec::new(),
        attacker_positions: vec![AttackerStartingPosition::new(
            "attacker",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("attacker", "db")],
    };

    let (initial_output, after_update) = assert_incremental_update_matches_recompute(
        facts,
        vec![FactUpdate::InsertVulnerability(VulnerabilityRecord::new(
            "db",
            "CVE-DB",
            "postgres",
            PrivilegeLevel::Root,
        ))],
    );

    assert!(!initial_output.goals_reached.contains_key(&reached("db")));
    assert!(after_update
        .exec_code
        .contains_key(&exec_on("db", PrivilegeLevel::Root)));
    assert!(after_update.goals_reached.contains_key(&reached("db")));
}

#[test]
fn alternate_path_patch_still_reaches_goal_and_matches_recompute() {
    let facts = BaseFacts {
        vulnerabilities: vec![
            VulnerabilityRecord::new("web_a", "CVE-WEB-A", "https", PrivilegeLevel::User),
            VulnerabilityRecord::new("web_b", "CVE-WEB-B", "https", PrivilegeLevel::User),
            VulnerabilityRecord::new("db", "CVE-DB", "postgres", PrivilegeLevel::Root),
        ],
        network_access: vec![
            NetworkAccessRule::new("internet", "web_a", "https"),
            NetworkAccessRule::new("internet", "web_b", "https"),
            NetworkAccessRule::new("web_a", "db", "postgres"),
            NetworkAccessRule::new("web_b", "db", "postgres"),
        ],
        firewall_rules: Vec::new(),
        attacker_positions: vec![AttackerStartingPosition::new(
            "attacker",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("attacker", "db")],
    };

    let (initial_output, after_update) = assert_incremental_update_matches_recompute(
        facts,
        vec![FactUpdate::RemoveVulnerability(VulnerabilityRecord::new(
            "web_a",
            "CVE-WEB-A",
            "https",
            PrivilegeLevel::User,
        ))],
    );

    assert!(initial_output
        .exec_code
        .contains_key(&exec_on("web_a", PrivilegeLevel::User)));
    assert!(after_update
        .exec_code
        .contains_key(&exec_on("web_b", PrivilegeLevel::User)));
    assert!(after_update
        .exec_code
        .contains_key(&exec_on("db", PrivilegeLevel::Root)));
    assert!(after_update.goals_reached.contains_key(&reached("db")));
}

#[test]
fn naive_oracle_matches_dataflow_on_simple_chain() {
    let mut facts = chain_base_facts();
    facts
        .network_access
        .push(NetworkAccessRule::new("web", "db", "postgres"));

    assert_dataflow_matches_naive(facts);
}

#[test]
fn naive_oracle_matches_dataflow_with_firewall_deny() {
    let mut facts = chain_base_facts();
    facts
        .network_access
        .push(NetworkAccessRule::new("web", "db", "postgres"));
    facts
        .firewall_rules
        .push(FirewallRuleRecord::create_deny_rule(
            "internet", "web", "https",
        ));

    assert_dataflow_matches_naive(facts);
}

#[test]
fn naive_oracle_matches_dataflow_with_alternate_path_patch() {
    let mut facts = BaseFacts {
        vulnerabilities: vec![
            VulnerabilityRecord::new("web_a", "CVE-WEB-A", "https", PrivilegeLevel::User),
            VulnerabilityRecord::new("web_b", "CVE-WEB-B", "https", PrivilegeLevel::User),
            VulnerabilityRecord::new("db", "CVE-DB", "postgres", PrivilegeLevel::Root),
        ],
        network_access: vec![
            NetworkAccessRule::new("internet", "web_a", "https"),
            NetworkAccessRule::new("internet", "web_b", "https"),
            NetworkAccessRule::new("web_a", "db", "postgres"),
            NetworkAccessRule::new("web_b", "db", "postgres"),
        ],
        firewall_rules: Vec::new(),
        attacker_positions: vec![AttackerStartingPosition::new(
            "attacker",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("attacker", "db")],
    };

    apply_updates_to_facts(
        &mut facts,
        &[FactUpdate::RemoveVulnerability(VulnerabilityRecord::new(
            "web_a",
            "CVE-WEB-A",
            "https",
            PrivilegeLevel::User,
        ))],
    );

    assert_dataflow_matches_naive(facts);
}
