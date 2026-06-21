use std::sync::{Arc, Mutex, OnceLock};

use differential_dataflow::input::Input;
use dynamic_attack_graphs::{
    build_attack_graph, AttackerCodeExecution, AttackerGoalReached, AttackerOwnsMachine,
    AttackerStartingPosition, AttackerTargetGoal, FirewallRuleRecord, NetworkAccessRule,
    PrivilegeLevel, VulnerabilityRecord,
};
use timely::dataflow::operators::probe::Handle;

#[derive(Debug, Default)]
struct CapturedChanges {
    exec_code: Vec<(AttackerCodeExecution, usize, isize)>,
    owns_machine: Vec<(AttackerOwnsMachine, usize, isize)>,
    goals_reached: Vec<(AttackerGoalReached, usize, isize)>,
}

static TIMELY_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn run_two_step_scenario<F>(apply_update: F) -> CapturedChanges
where
    F: FnOnce(
            &mut differential_dataflow::input::InputSession<usize, VulnerabilityRecord, isize>,
            &mut differential_dataflow::input::InputSession<usize, NetworkAccessRule, isize>,
            &mut differential_dataflow::input::InputSession<usize, FirewallRuleRecord, isize>,
        ) + Send
        + Sync
        + 'static,
{
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

            owns_machine.inspect(move |(record, time, diff)| {
                captured_owns
                    .lock()
                    .expect("captured ownership changes mutex should not be poisoned")
                    .owns_machine
                    .push((record.clone(), *time, *diff));
            });

            goals_reached.inspect(move |(record, time, diff)| {
                captured_goals
                    .lock()
                    .expect("captured goal changes mutex should not be poisoned")
                    .goals_reached
                    .push((record.clone(), *time, *diff));
            });

            (
                vulnerability_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        network_input.insert(NetworkAccessRule::new("internet", "web", "https"));
        network_input.insert(NetworkAccessRule::new("web", "db", "postgres"));

        vulnerability_input.insert(VulnerabilityRecord::new(
            "web",
            "CVE-WEB",
            "https",
            PrivilegeLevel::User,
        ));
        vulnerability_input.insert(VulnerabilityRecord::new(
            "db",
            "CVE-DB",
            "postgres",
            PrivilegeLevel::Root,
        ));

        attacker_position_input.insert(AttackerStartingPosition::new(
            "eve",
            "internet",
            PrivilegeLevel::User,
        ));
        attacker_goal_input.insert(AttackerTargetGoal::new("eve", "db"));

        vulnerability_input.advance_to(1);
        network_input.advance_to(1);
        firewall_input.advance_to(1);
        attacker_position_input.advance_to(1);
        attacker_goal_input.advance_to(1);
        vulnerability_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        while probe.less_than(&1) {
            worker.step();
        }

        apply_update(
            &mut vulnerability_input,
            &mut network_input,
            &mut firewall_input,
        );

        vulnerability_input.advance_to(2);
        network_input.advance_to(2);
        firewall_input.advance_to(2);
        attacker_position_input.advance_to(2);
        attacker_goal_input.advance_to(2);
        vulnerability_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        while probe.less_than(&2) {
            worker.step();
        }
    });

    Arc::try_unwrap(captured_after_run)
        .expect("test should hold the only captured-change reference")
        .into_inner()
        .expect("captured changes mutex should not be poisoned")
}

#[test]
fn initial_rules_reach_goal_through_vulnerable_chain() {
    let changes = run_two_step_scenario(|_, _, _| {});

    assert!(changes.exec_code.contains(&(
        AttackerCodeExecution {
            attacker_id: "eve".to_string(),
            compromised_host: "web".to_string(),
            obtained_privilege: PrivilegeLevel::User,
        },
        0,
        1,
    )));
    assert!(changes.owns_machine.contains(&(
        AttackerOwnsMachine {
            attacker_id: "eve".to_string(),
            owned_host: "db".to_string(),
        },
        0,
        1,
    )));
    assert!(changes.goals_reached.contains(&(
        AttackerGoalReached {
            attacker_id: "eve".to_string(),
            reached_target: "db".to_string(),
        },
        0,
        1,
    )));
}

#[test]
fn adding_firewall_deny_retracts_dependent_compromise() {
    let changes = run_two_step_scenario(|_, _, firewall_input| {
        firewall_input.insert(FirewallRuleRecord::create_deny_rule(
            "internet", "web", "https",
        ));
    });

    assert!(changes.exec_code.contains(&(
        AttackerCodeExecution {
            attacker_id: "eve".to_string(),
            compromised_host: "web".to_string(),
            obtained_privilege: PrivilegeLevel::User,
        },
        1,
        -1,
    )));
    assert!(changes.goals_reached.contains(&(
        AttackerGoalReached {
            attacker_id: "eve".to_string(),
            reached_target: "db".to_string(),
        },
        1,
        -1,
    )));
}

#[test]
fn patching_intermediate_vulnerability_retracts_downstream_goal() {
    let changes = run_two_step_scenario(|vulnerability_input, _, _| {
        vulnerability_input.remove(VulnerabilityRecord::new(
            "web",
            "CVE-WEB",
            "https",
            PrivilegeLevel::User,
        ));
    });

    assert!(changes.exec_code.contains(&(
        AttackerCodeExecution {
            attacker_id: "eve".to_string(),
            compromised_host: "db".to_string(),
            obtained_privilege: PrivilegeLevel::Root,
        },
        1,
        -1,
    )));
    assert!(changes.owns_machine.contains(&(
        AttackerOwnsMachine {
            attacker_id: "eve".to_string(),
            owned_host: "db".to_string(),
        },
        1,
        -1,
    )));
    assert!(changes.goals_reached.contains(&(
        AttackerGoalReached {
            attacker_id: "eve".to_string(),
            reached_target: "db".to_string(),
        },
        1,
        -1,
    )));
}
