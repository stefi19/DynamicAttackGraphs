use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use differential_dataflow::input::Input;
use timely::dataflow::operators::probe::Handle;

use crate::engine::{
    effective_network_access_from_base, AttackGraphEngine, BaseFacts, DerivedFacts, FactUpdate,
};
use crate::rules::build_attack_graph_with_local_vulnerabilities;
use crate::schema::{
    AttackerCodeExecution, AttackerGoalReached, AttackerOwnsMachine, AttackerStartingPosition,
    AttackerTargetGoal, FirewallRuleRecord, LocalVulnerabilityRecord, NetworkAccessRule,
    VulnerabilityRecord,
};

static DIFFERENTIAL_ENGINE_RUNTIME_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Default)]
pub struct DifferentialEngine {
    facts: BaseFacts,
}

#[derive(Debug, Default)]
struct CapturedOutput {
    code_executions: Vec<(AttackerCodeExecution, isize)>,
    machines_owned: Vec<(AttackerOwnsMachine, isize)>,
    goals_reached: Vec<(AttackerGoalReached, isize)>,
}

impl DifferentialEngine {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AttackGraphEngine for DifferentialEngine {
    fn name(&self) -> &'static str {
        "differential-dataflow"
    }

    fn load_snapshot(&mut self, facts: BaseFacts) {
        self.facts = facts;
    }

    fn apply_update(&mut self, update: FactUpdate) {
        self.facts.apply_update(update);
    }

    fn current_derived_facts(&self) -> DerivedFacts {
        evaluate_with_differential_dataflow(&self.facts)
    }
}

fn evaluate_with_differential_dataflow(facts: &BaseFacts) -> DerivedFacts {
    let _runtime_guard = DIFFERENTIAL_ENGINE_RUNTIME_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("differential engine runtime lock should not be poisoned");

    let captured = Arc::new(Mutex::new(CapturedOutput::default()));
    let captured_after_run = Arc::clone(&captured);
    let effective_access = effective_network_access_from_base(facts);
    let facts = facts.clone();

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
                .inspect(move |(record, _time, diff)| {
                    captured_exec
                        .lock()
                        .expect("captured exec output mutex should not be poisoned")
                        .code_executions
                        .push((record.clone(), *diff));
                })
                .probe_with(&mut probe);

            owns_machine
                .inspect(move |(record, _time, diff)| {
                    captured_owns
                        .lock()
                        .expect("captured ownership output mutex should not be poisoned")
                        .machines_owned
                        .push((record.clone(), *diff));
                })
                .probe_with(&mut probe);

            goals_reached
                .inspect(move |(record, _time, diff)| {
                    captured_goals
                        .lock()
                        .expect("captured goal output mutex should not be poisoned")
                        .goals_reached
                        .push((record.clone(), *diff));
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

        for vulnerability in &facts.vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for vulnerability in &facts.local_vulnerabilities {
            local_vulnerability_input.insert(vulnerability.clone());
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
        .expect("differential engine should hold the only captured-output reference")
        .into_inner()
        .expect("captured output mutex should not be poisoned");

    DerivedFacts {
        effective_network_access: effective_access,
        code_executions: positive_records(captured.code_executions),
        machines_owned: positive_records(captured.machines_owned),
        goals_reached: positive_records(captured.goals_reached),
    }
}

fn positive_records<T>(updates: Vec<(T, isize)>) -> std::collections::HashSet<T>
where
    T: Eq + std::hash::Hash + Clone,
{
    let mut counts = HashMap::new();
    for (record, diff) in updates {
        *counts.entry(record).or_insert(0) += diff;
    }
    counts
        .into_iter()
        .filter_map(|(record, count)| (count > 0).then_some(record))
        .collect()
}
