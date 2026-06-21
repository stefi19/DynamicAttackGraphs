use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use differential_dataflow::input::Input;
use dynamic_attack_graphs::{
    build_attack_graph_with_local_vulnerabilities,
    evaluate_attack_graph_naive_with_local_vulnerabilities, AttackerCodeExecution,
    AttackerGoalReached, AttackerOwnsMachine, AttackerStartingPosition, AttackerTargetGoal,
    FirewallRuleRecord, LocalVulnerabilityRecord, NetworkAccessRule, PrivilegeLevel,
    VulnerabilityRecord,
};
use timely::dataflow::operators::probe::Handle;

#[derive(Debug, Clone, Default)]
struct LocalEscalationFacts {
    vulnerabilities: Vec<VulnerabilityRecord>,
    local_vulnerabilities: Vec<LocalVulnerabilityRecord>,
    network_access: Vec<NetworkAccessRule>,
    firewall_rules: Vec<FirewallRuleRecord>,
    attacker_positions: Vec<AttackerStartingPosition>,
    attacker_goals: Vec<AttackerTargetGoal>,
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

fn collect_dataflow_output(facts: LocalEscalationFacts) -> AttackGraphOutput {
    let _runtime_guard = TIMELY_TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("timely test runtime lock should not be poisoned");

    let captured = Arc::new(Mutex::new(CapturedChanges::default()));
    let captured_after_run = Arc::clone(&captured);

    timely::execute_directly(move |worker| {
        let mut probe = Handle::new();

        let captured_exec = Arc::clone(&captured);
        let captured_owns = Arc::clone(&captured);
        let captured_goals = Arc::clone(&captured);

        let (
            mut vulnerability_input,
            mut local_vulnerability_input,
            mut network_input,
            mut firewall_input,
            mut attacker_position_input,
            mut attacker_goal_input,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            let (vulnerability_handle, vulnerability_collection) =
                scope.new_collection::<VulnerabilityRecord, isize>();
            let (local_vulnerability_handle, local_vulnerability_collection) =
                scope.new_collection::<LocalVulnerabilityRecord, isize>();
            let (network_handle, network_collection) =
                scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) =
                scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) =
                scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) =
                scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, owns_machine, goals_reached) =
                build_attack_graph_with_local_vulnerabilities(
                    &vulnerability_collection,
                    &local_vulnerability_collection,
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
                local_vulnerability_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        for vulnerability in facts.vulnerabilities {
            vulnerability_input.insert(vulnerability);
        }
        for vulnerability in facts.local_vulnerabilities {
            local_vulnerability_input.insert(vulnerability);
        }
        for access in facts.network_access {
            network_input.insert(access);
        }
        for rule in facts.firewall_rules {
            firewall_input.insert(rule);
        }
        for position in facts.attacker_positions {
            attacker_position_input.insert(position);
        }
        for goal in facts.attacker_goals {
            attacker_goal_input.insert(goal);
        }

        vulnerability_input.advance_to(1);
        local_vulnerability_input.advance_to(1);
        network_input.advance_to(1);
        firewall_input.advance_to(1);
        attacker_position_input.advance_to(1);
        attacker_goal_input.advance_to(1);

        vulnerability_input.flush();
        local_vulnerability_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        while probe.less_than(&1) {
            worker.step();
        }
    });

    let captured = Arc::try_unwrap(captured_after_run)
        .expect("test should hold the only captured-change reference")
        .into_inner()
        .expect("captured changes mutex should not be poisoned");

    AttackGraphOutput {
        exec_code: consolidate(captured.exec_code),
        owns_machine: consolidate(captured.owns_machine),
        goals_reached: consolidate(captured.goals_reached),
    }
}

fn consolidate<T: Ord>(changes: Vec<(T, usize, isize)>) -> BTreeMap<T, isize> {
    let mut output = BTreeMap::new();

    for (record, _time, diff) in changes {
        *output.entry(record).or_insert(0) += diff;
    }

    output.retain(|_, diff| *diff != 0);
    output
}

fn local_escalation_facts() -> LocalEscalationFacts {
    LocalEscalationFacts {
        vulnerabilities: vec![VulnerabilityRecord::new(
            "web01",
            "cve_2024_web",
            "https",
            PrivilegeLevel::User,
        )],
        local_vulnerabilities: vec![LocalVulnerabilityRecord::new(
            "web01",
            "cve_2024_local",
            PrivilegeLevel::Root,
        )],
        network_access: vec![NetworkAccessRule::new("internet", "web01", "https")],
        firewall_rules: Vec::new(),
        attacker_positions: vec![AttackerStartingPosition::new(
            "eve",
            "internet",
            PrivilegeLevel::User,
        )],
        attacker_goals: vec![AttackerTargetGoal::new("eve", "web01")],
    }
}

fn exec(attacker_id: &str, host: &str, privilege: PrivilegeLevel) -> AttackerCodeExecution {
    AttackerCodeExecution {
        attacker_id: attacker_id.to_string(),
        compromised_host: host.to_string(),
        obtained_privilege: privilege,
    }
}

fn owns(attacker_id: &str, host: &str) -> AttackerOwnsMachine {
    AttackerOwnsMachine {
        attacker_id: attacker_id.to_string(),
        owned_host: host.to_string(),
    }
}

fn reached(attacker_id: &str, host: &str) -> AttackerGoalReached {
    AttackerGoalReached {
        attacker_id: attacker_id.to_string(),
        reached_target: host.to_string(),
    }
}

#[test]
fn local_privilege_escalation_works_after_user_access() {
    let output = collect_dataflow_output(local_escalation_facts());

    assert!(output
        .exec_code
        .contains_key(&exec("eve", "web01", PrivilegeLevel::User)));
    assert!(output
        .exec_code
        .contains_key(&exec("eve", "web01", PrivilegeLevel::Root)));
    assert!(output.owns_machine.contains_key(&owns("eve", "web01")));
    assert!(output.goals_reached.contains_key(&reached("eve", "web01")));
}

#[test]
fn local_privilege_escalation_requires_prior_access() {
    let mut facts = local_escalation_facts();
    facts.vulnerabilities.clear();

    let output = collect_dataflow_output(facts);

    assert!(!output
        .exec_code
        .contains_key(&exec("eve", "web01", PrivilegeLevel::User)));
    assert!(!output
        .exec_code
        .contains_key(&exec("eve", "web01", PrivilegeLevel::Root)));
    assert!(!output.owns_machine.contains_key(&owns("eve", "web01")));
    assert!(!output.goals_reached.contains_key(&reached("eve", "web01")));
}

#[test]
fn local_privilege_escalation_matches_naive_evaluator() {
    let facts = local_escalation_facts();
    let dataflow_output = collect_dataflow_output(facts.clone());
    let naive_output = evaluate_attack_graph_naive_with_local_vulnerabilities(
        facts.vulnerabilities,
        facts.local_vulnerabilities,
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
