// Benchmark module for measuring incremental vs full recomputation
// ----------------------------------------------------------------
// This module contains helper functions and small benchmarks that
// generate synthetic network topologies (chain, star, mesh) and run
// the dataflow to measure the wall-clock time for (a) computing the
// full attack graph from scratch and (b) performing a small
// incremental update (e.g. patching a vulnerability).  The
// measurements form the empirical evidence used in the paper.

use std::time::{Duration, Instant};

use differential_dataflow::input::Input;
use timely::dataflow::operators::probe::Handle;

use crate::rules::build_attack_graph;
use crate::schema::*;

#[derive(Debug, Clone)]
pub struct FullRecomputationResult {
    pub computation_time: Duration,
    pub derived_fact_count: usize,
}

// Results produced by a single benchmark run.  These are used to
// create the tables and figures in the paper.
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub number_of_nodes: usize,
    pub initial_computation_time: Duration,
    pub incremental_update_time: Duration,
    pub speedup_factor: f64,
    // simple counts useful for debugging/plots
    pub number_of_attack_paths_initial: usize,
    pub number_of_attack_paths_after_patch: usize,
}

impl BenchmarkResults {
    // Pretty-print a concise summary for quick CLI inspection
    pub fn print_summary(&self) {
        println!("=== BENCHMARK RESULTS ===");
        println!("Network size: {} nodes", self.number_of_nodes);
        println!("Initial computation: {:?}", self.initial_computation_time);
        println!("Incremental update:  {:?}", self.incremental_update_time);
        println!("Speedup factor: {:.2}x", self.speedup_factor);
        println!(
            "Attack paths (initial): {}",
            self.number_of_attack_paths_initial
        );
        println!(
            "Attack paths (after patch): {}",
            self.number_of_attack_paths_after_patch
        );
        println!();
    }
}

// ----------------------------------------------------------------
// Topology generators
// ----------------------------------------------------------------
// These helper functions produce small synthetic networks and
// corresponding vulnerability / attacker facts.  They are intentionally
// simple and deterministic so the benchmarks are reproducible.

// Chain: node_0 -> node_1 -> node_2 -> ... -> node_n
// Each node has a vulnerability and the attacker starts at node_0.
// This is the worst-case topology for incremental updates because a
// cut near the root invalidates many downstream facts.
pub fn generate_chain_network(
    number_of_nodes: usize,
) -> (
    Vec<NetworkAccessRule>,
    Vec<VulnerabilityRecord>,
    Vec<AttackerStartingPosition>,
    Vec<AttackerTargetGoal>,
) {
    let mut network_topology = Vec::with_capacity(number_of_nodes - 1);
    let mut vulnerabilities = Vec::with_capacity(number_of_nodes);

    // Build nodes and edges
    for node_index in 0..number_of_nodes {
        let node_name = format!("node_{}", node_index);

        // Give each node a vulnerability that yields Root when
        // exploited.  The benchmark is synthetic: privileges are
        // chosen to highlight propagation costs rather than realistic
        // vulnerability semantics.
        vulnerabilities.push(VulnerabilityRecord::new(
            &node_name,
            &format!("CVE-CHAIN-{}", node_index),
            "ssh",
            PrivilegeLevel::Root,
        ));

        // Add directed edge to next node (except for last)
        if node_index < number_of_nodes - 1 {
            let next_node_name = format!("node_{}", node_index + 1);
            network_topology.push(NetworkAccessRule::new(&node_name, &next_node_name, "ssh"));
        }
    }

    // Attacker starts at node_0 with Root privileges in the benchmark
    // (this models an already-compromised host or insider threat).
    let attacker_positions = vec![AttackerStartingPosition::new(
        "attacker",
        "node_0",
        PrivilegeLevel::Root,
    )];

    // Goal: reach the last node in the chain
    let attacker_goals = vec![AttackerTargetGoal::new(
        "attacker",
        &format!("node_{}", number_of_nodes - 1),
    )];

    (
        network_topology,
        vulnerabilities,
        attacker_positions,
        attacker_goals,
    )
}

// Mesh and star generators are similar: they create repeatable,
// deterministic topologies used by other benchmarks in the paper.
// The implementations below are intentionally straightforward and
// well-commented to help a reader adapt them for other experiments.
pub fn generate_mesh_network(
    grid_width: usize,
    grid_height: usize,
) -> (
    Vec<NetworkAccessRule>,
    Vec<VulnerabilityRecord>,
    Vec<AttackerStartingPosition>,
    Vec<AttackerTargetGoal>,
) {
    let total_nodes = grid_width * grid_height;
    let mut network_topology = Vec::new();
    let mut vulnerabilities = Vec::with_capacity(total_nodes);

    // Helper to get node name from grid coordinates
    let node_name = |x: usize, y: usize| format!("node_{}_{}", x, y);

    for y in 0..grid_height {
        for x in 0..grid_width {
            let current_node = node_name(x, y);

            // assign vulnerability per node
            vulnerabilities.push(VulnerabilityRecord::new(
                &current_node,
                &format!("CVE-MESH-{}-{}", x, y),
                "ssh",
                PrivilegeLevel::Root,
            ));

            // connect to right neighbor
            if x + 1 < grid_width {
                network_topology.push(NetworkAccessRule::new(
                    &current_node,
                    &node_name(x + 1, y),
                    "ssh",
                ));
            }

            // connect to bottom neighbor
            if y + 1 < grid_height {
                network_topology.push(NetworkAccessRule::new(
                    &current_node,
                    &node_name(x, y + 1),
                    "ssh",
                ));
            }
        }
    }

    let attacker_positions = vec![AttackerStartingPosition::new(
        "attacker",
        "node_0_0",
        PrivilegeLevel::Root,
    )];

    let attacker_goals = vec![AttackerTargetGoal::new(
        "attacker",
        &node_name(grid_width - 1, grid_height - 1),
    )];

    (
        network_topology,
        vulnerabilities,
        attacker_positions,
        attacker_goals,
    )
}

pub fn generate_star_network(
    number_of_leaves: usize,
) -> (
    Vec<NetworkAccessRule>,
    Vec<VulnerabilityRecord>,
    Vec<AttackerStartingPosition>,
    Vec<AttackerTargetGoal>,
) {
    let mut network_topology = Vec::with_capacity(number_of_leaves);
    let mut vulnerabilities = Vec::with_capacity(number_of_leaves + 1);

    // Central hub has a vuln
    vulnerabilities.push(VulnerabilityRecord::new(
        "hub",
        "CVE-HUB-0",
        "ssh",
        PrivilegeLevel::Root,
    ));

    // Create leaves: each leaf has a vulnerability and an edge from
    // the hub to the leaf.  In a star topology, the attack depth is
    // small (constant) so incremental updates are very cheap.
    for leaf_index in 0..number_of_leaves {
        let leaf_name = format!("leaf_{}", leaf_index);

        vulnerabilities.push(VulnerabilityRecord::new(
            &leaf_name,
            &format!("CVE-LEAF-{}", leaf_index),
            "ssh",
            PrivilegeLevel::Root,
        ));

        network_topology.push(NetworkAccessRule::new("hub", &leaf_name, "ssh"));
    }

    let attacker_positions = vec![AttackerStartingPosition::new(
        "attacker",
        "hub",
        PrivilegeLevel::Root,
    )];

    let attacker_goals = vec![AttackerTargetGoal::new(
        "attacker",
        &format!("leaf_{}", number_of_leaves - 1),
    )];

    (
        network_topology,
        vulnerabilities,
        attacker_positions,
        attacker_goals,
    )
}

// ----------------------------------------------------------------
// Benchmarks that execute the dataflow
// ----------------------------------------------------------------
// We use `timely::execute_directly` to run a single-worker instance of
// the timely/differential runtime.  This avoids thread scheduling
// nondeterminism during microbenchmarks and makes timings more
// repeatable for the paper.  The pattern is:
//
// 1. Create a new dataflow with `scope.new_collection()` handles
// 2. Insert initial data and `advance_to(1)` to signal completion
// 3. Use a `ProbeHandle` and `worker.step()` loop to wait for
//    completion of a logical time
// 4. Perform an incremental change, `advance_to(2)`, and wait again
//
// The code below mirrors this pattern for different topologies.

// Rebuild the attack graph from scratch with the supplied facts.
// This deliberately creates a fresh dataflow instance, so the timing is
// a full recomputation baseline rather than an incremental update.
pub fn measure_full_recomputation(
    network_topology: &[NetworkAccessRule],
    vulnerabilities: &[VulnerabilityRecord],
    firewall_rules: &[FirewallRuleRecord],
    attacker_positions: &[AttackerStartingPosition],
    attacker_goals: &[AttackerTargetGoal],
) -> FullRecomputationResult {
    use std::sync::{Arc, Mutex};

    let network_topology = network_topology.to_vec();
    let vulnerabilities = vulnerabilities.to_vec();
    let firewall_rules = firewall_rules.to_vec();
    let attacker_positions = attacker_positions.to_vec();
    let attacker_goals = attacker_goals.to_vec();

    timely::execute_directly(move |worker| {
        let derived_fact_count = Arc::new(Mutex::new(0usize));
        let exec_count = Arc::clone(&derived_fact_count);
        let owns_count = Arc::clone(&derived_fact_count);
        let goal_count = Arc::clone(&derived_fact_count);

        let mut probe = Handle::new();

        let (
            mut vulnerability_input,
            mut network_input,
            mut firewall_input,
            mut attacker_position_input,
            mut attacker_goal_input,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            let (vuln_handle, vuln_collection) =
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
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code.consolidate().inspect(move |(_, _, diff)| {
                if *diff > 0 {
                    *exec_count.lock().unwrap() += *diff as usize;
                }
            });
            owns_machine.consolidate().inspect(move |(_, _, diff)| {
                if *diff > 0 {
                    *owns_count.lock().unwrap() += *diff as usize;
                }
            });
            goals_reached
                .consolidate()
                .inspect(move |(_, _, diff)| {
                    if *diff > 0 {
                        *goal_count.lock().unwrap() += *diff as usize;
                    }
                })
                .probe_with(&mut probe);

            (
                vuln_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        let start = Instant::now();

        for network_rule in &network_topology {
            network_input.insert(network_rule.clone());
        }
        for vulnerability in &vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for firewall_rule in &firewall_rules {
            firewall_input.insert(firewall_rule.clone());
        }
        for position in &attacker_positions {
            attacker_position_input.insert(position.clone());
        }
        for goal in &attacker_goals {
            attacker_goal_input.insert(goal.clone());
        }

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

        let derived_fact_count = *derived_fact_count.lock().unwrap();

        FullRecomputationResult {
            computation_time: start.elapsed(),
            derived_fact_count,
        }
    })
}

// Run the chain benchmark: measure initial build time and the time
// to perform a single incremental patch (remove vulnerability at
// node_1).  The timings are returned in a `BenchmarkResults` struct.
pub fn run_chain_benchmark(number_of_nodes: usize) -> BenchmarkResults {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let (network_topology, vulnerabilities, attacker_positions, attacker_goals) =
        generate_chain_network(number_of_nodes);

    // We use atomic/u64s to capture timings inside the timely worker
    // closure because `execute_directly` takes ownership and runs on
    // the current thread.
    let initial_nanos = Arc::new(AtomicU64::new(0));
    let incremental_nanos = Arc::new(AtomicU64::new(0));
    let initial_clone = Arc::clone(&initial_nanos);
    let incremental_clone = Arc::clone(&incremental_nanos);

    // Execute the dataflow synchronously on the current thread
    timely::execute_directly(move |worker| {
        // ProbeHandle allows us to wait until the dataflow has
        // processed all updates up to a given logical time.
        let mut probe = Handle::new();

        // Create input handles and collections inside a single dataflow
        let (
            mut vulnerability_input,
            mut network_input,
            mut firewall_input,
            mut attacker_position_input,
            mut attacker_goal_input,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            // Each `new_collection` returns a handle that we can use
            // to insert/remove/advance data from outside the dataflow
            // and a `Collection` view that we pass to `build_attack_graph`.
            let (vuln_handle, vuln_collection) =
                scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) =
                scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) =
                scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) =
                scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) =
                scope.new_collection::<AttackerTargetGoal, isize>();

            // Wire the collections into the rules implementation
            let (exec_code, _owns_machine, _goals_reached) = build_attack_graph(
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            // Attach a probe to one of the outputs so we can wait for
            // the computation to finish up to a logical time.
            exec_code.consolidate().probe_with(&mut probe);

            (
                vuln_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        // ------------------ Phase 1: initial computation ------------------
        let start_initial = Instant::now();

        // Bulk-insert initial facts using the input handles
        for network_rule in &network_topology {
            network_input.insert(network_rule.clone());
        }
        for vulnerability in &vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for position in &attacker_positions {
            attacker_position_input.insert(position.clone());
        }
        for goal in &attacker_goals {
            attacker_goal_input.insert(goal.clone());
        }

        // Advance logical time to 1 and flush buffers so the dataflow
        // sees a consistent snapshot for the initial computation.
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

        // Wait until the probe indicates all updates for time 1 are processed
        while probe.less_than(&1) {
            worker.step();
        }

        let initial_elapsed = start_initial.elapsed();

        // ------------------ Phase 2: incremental update ------------------
        // Simulate a "patch" by removing the vulnerability on node_1.
        let start_incremental = Instant::now();

        vulnerability_input.remove(VulnerabilityRecord::new(
            "node_1",
            "CVE-CHAIN-1",
            "ssh",
            PrivilegeLevel::Root,
        ));

        // Advance to logical time 2 for the incremental update
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

        // Wait until the incremental update has been processed
        while probe.less_than(&2) {
            worker.step();
        }

        let incremental_elapsed = start_incremental.elapsed();

        // Store the timings in the outer-scoped atomics
        initial_clone.store(initial_elapsed.as_nanos() as u64, Ordering::SeqCst);
        incremental_clone.store(incremental_elapsed.as_nanos() as u64, Ordering::SeqCst);
    });

    // Convert stored nanoseconds into Duration for the return value
    let initial_time = Duration::from_nanos(initial_nanos.load(Ordering::SeqCst));
    let incremental_time = Duration::from_nanos(incremental_nanos.load(Ordering::SeqCst));

    let speedup = if incremental_time.as_nanos() > 0 {
        initial_time.as_secs_f64() / incremental_time.as_secs_f64()
    } else {
        f64::INFINITY
    };

    BenchmarkResults {
        number_of_nodes,
        initial_computation_time: initial_time,
        incremental_update_time: incremental_time,
        speedup_factor: speedup,
        number_of_attack_paths_initial: number_of_nodes,
        number_of_attack_paths_after_patch: 1,
    }
}

// Run multiple benchmarks with increasing sizes (helper)
pub fn run_scalability_benchmark(sizes: &[usize]) -> Vec<BenchmarkResults> {
    sizes
        .iter()
        .map(|&size| run_chain_benchmark(size))
        .collect()
}

// ----------------------------------------------------------------
// Random-cut benchmark (chain topology)
// ----------------------------------------------------------------
// This benchmark repeatedly selects a random node k and removes the
// vulnerability at node_k.  The cost of the incremental update
// depends on k: removing near the start of the chain invalidates
// more downstream facts than removing near the end.

#[derive(Debug, Clone)]
pub struct RandomCutBenchmarkResults {
    pub number_of_nodes: usize,
    pub number_of_iterations: usize,
    pub initial_computation_time: Duration,
    pub average_incremental_time: Duration,
    pub min_incremental_time: Duration,
    pub max_incremental_time: Duration,
    pub average_speedup: f64,
}

pub fn run_chain_random_cut_benchmark(
    number_of_nodes: usize,
    iterations: usize,
) -> RandomCutBenchmarkResults {
    use rand::Rng;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let (network_topology, vulnerabilities, attacker_positions, attacker_goals) =
        generate_chain_network(number_of_nodes);

    // Storage for timing data across iterations
    let initial_nanos = Arc::new(AtomicU64::new(0));
    let incremental_times_nanos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let initial_clone = Arc::clone(&initial_nanos);
    let times_clone = Arc::clone(&incremental_times_nanos);

    let iterations_count = iterations;

    timely::execute_directly(move |worker| {
        let mut probe = Handle::new();

        let (
            mut vulnerability_input,
            mut network_input,
            mut firewall_input,
            mut attacker_position_input,
            mut attacker_goal_input,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            let (vuln_handle, vuln_collection) =
                scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) =
                scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) =
                scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) =
                scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) =
                scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, _owns_machine, _goals_reached) = build_attack_graph(
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code.consolidate().probe_with(&mut probe);

            (
                vuln_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        // Phase 1: initial computation (identical to the single-shot benchmark)
        let start_initial = Instant::now();

        for network_rule in &network_topology {
            network_input.insert(network_rule.clone());
        }
        for vulnerability in &vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for position in &attacker_positions {
            attacker_position_input.insert(position.clone());
        }
        for goal in &attacker_goals {
            attacker_goal_input.insert(goal.clone());
        }

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

        let initial_elapsed = start_initial.elapsed();
        initial_clone.store(initial_elapsed.as_nanos() as u64, Ordering::SeqCst);

        // Phase 2: Multiple random cut tests
        let mut rng = rand::thread_rng();
        let mut times_vec = times_clone.lock().unwrap();

        for i in 0..iterations_count {
            let time_step = 2 + (i * 2); // Each iteration uses 2 time steps

            // Pick a random node k between 0 and number_of_nodes - 1
            let k = rng.gen_range(0..number_of_nodes);
            let node_name = format!("node_{}", k);
            let cve_name = format!("CVE-CHAIN-{}", k);

            // Remove vulnerability at node k (cuts chain at position k)
            let start_incremental = Instant::now();

            vulnerability_input.remove(VulnerabilityRecord::new(
                &node_name,
                &cve_name,
                "ssh",
                PrivilegeLevel::Root,
            ));

            vulnerability_input.advance_to(time_step);
            network_input.advance_to(time_step);
            firewall_input.advance_to(time_step);
            attacker_position_input.advance_to(time_step);
            attacker_goal_input.advance_to(time_step);
            vulnerability_input.flush();
            network_input.flush();
            firewall_input.flush();
            attacker_position_input.flush();
            attacker_goal_input.flush();

            while probe.less_than(&time_step) {
                worker.step();
            }

            let incremental_elapsed = start_incremental.elapsed();
            times_vec.push(incremental_elapsed.as_nanos() as u64);

            // Re-add the vulnerability to restore the chain for next iteration
            vulnerability_input.insert(VulnerabilityRecord::new(
                &node_name,
                &cve_name,
                "ssh",
                PrivilegeLevel::Root,
            ));

            vulnerability_input.advance_to(time_step + 1);
            network_input.advance_to(time_step + 1);
            firewall_input.advance_to(time_step + 1);
            attacker_position_input.advance_to(time_step + 1);
            attacker_goal_input.advance_to(time_step + 1);
            vulnerability_input.flush();
            network_input.flush();
            firewall_input.flush();
            attacker_position_input.flush();
            attacker_goal_input.flush();

            while probe.less_than(&(time_step + 1)) {
                worker.step();
            }
        }
    });

    let initial_time = Duration::from_nanos(initial_nanos.load(Ordering::SeqCst));
    let times = incremental_times_nanos.lock().unwrap();

    let min_nanos = *times.iter().min().unwrap_or(&0);
    let max_nanos = *times.iter().max().unwrap_or(&0);
    let avg_nanos = if times.is_empty() {
        0
    } else {
        times.iter().sum::<u64>() / times.len() as u64
    };

    let avg_incremental = Duration::from_nanos(avg_nanos);
    let average_speedup = if avg_nanos > 0 {
        initial_time.as_secs_f64() / avg_incremental.as_secs_f64()
    } else {
        f64::INFINITY
    };

    RandomCutBenchmarkResults {
        number_of_nodes,
        number_of_iterations: iterations,
        initial_computation_time: initial_time,
        average_incremental_time: avg_incremental,
        min_incremental_time: Duration::from_nanos(min_nanos),
        max_incremental_time: Duration::from_nanos(max_nanos),
        average_speedup,
    }
}

// Print results table for random cut benchmark
pub fn print_random_cut_benchmark_table(results: &[RandomCutBenchmarkResults]) {
    println!(
        "| Nodes | Iterations | Initial (ms) | Avg Incr (us) | Min (us) | Max (us) | Avg Speedup |"
    );
    println!(
        "|-------|------------|--------------|---------------|----------|----------|-------------|"
    );
    for result in results {
        println!(
            "| {:>5} | {:>10} | {:>12.2} | {:>13.2} | {:>8.2} | {:>8.2} | {:>11.1}x |",
            result.number_of_nodes,
            result.number_of_iterations,
            result.initial_computation_time.as_secs_f64() * 1000.0,
            result.average_incremental_time.as_secs_f64() * 1_000_000.0,
            result.min_incremental_time.as_secs_f64() * 1_000_000.0,
            result.max_incremental_time.as_secs_f64() * 1_000_000.0,
            result.average_speedup,
        );
    }
}

// Run star benchmark - converges in O(1) iterations, good for large N
pub fn run_star_benchmark(number_of_leaves: usize) -> BenchmarkResults {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let (network_topology, vulnerabilities, attacker_positions, attacker_goals) =
        generate_star_network(number_of_leaves);

    let total_nodes = number_of_leaves + 1; // leaves + hub

    // Use atomics to share timing data (thread-safe)
    let initial_nanos = Arc::new(AtomicU64::new(0));
    let incremental_nanos = Arc::new(AtomicU64::new(0));
    let initial_clone = Arc::clone(&initial_nanos);
    let incremental_clone = Arc::clone(&incremental_nanos);

    timely::execute_directly(move |worker| {
        let mut probe = Handle::new();

        let (
            mut vulnerability_input,
            mut network_input,
            mut firewall_input,
            mut attacker_position_input,
            mut attacker_goal_input,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            let (vuln_handle, vuln_collection) =
                scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) =
                scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) =
                scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) =
                scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) =
                scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, _owns_machine, _goals_reached) = build_attack_graph(
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code.consolidate().probe_with(&mut probe);

            (
                vuln_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
            )
        });

        // Phase 1: Initial computation
        let start_initial = Instant::now();

        for network_rule in &network_topology {
            network_input.insert(network_rule.clone());
        }
        for vulnerability in &vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for position in &attacker_positions {
            attacker_position_input.insert(position.clone());
        }
        for goal in &attacker_goals {
            attacker_goal_input.insert(goal.clone());
        }

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

        let initial_elapsed = start_initial.elapsed();

        // Phase 2: Incremental update - patch vulnerability on leaf_0
        let start_incremental = Instant::now();

        vulnerability_input.remove(VulnerabilityRecord::new(
            "leaf_0",
            "CVE-LEAF-0",
            "ssh",
            PrivilegeLevel::Root,
        ));

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

        let incremental_elapsed = start_incremental.elapsed();
        initial_clone.store(initial_elapsed.as_nanos() as u64, Ordering::SeqCst);
        incremental_clone.store(incremental_elapsed.as_nanos() as u64, Ordering::SeqCst);
    });

    let initial_time = Duration::from_nanos(initial_nanos.load(Ordering::SeqCst));
    let incremental_time = Duration::from_nanos(incremental_nanos.load(Ordering::SeqCst));

    let speedup = if incremental_time.as_nanos() > 0 {
        initial_time.as_secs_f64() / incremental_time.as_secs_f64()
    } else {
        f64::INFINITY
    };

    BenchmarkResults {
        number_of_nodes: total_nodes,
        initial_computation_time: initial_time,
        incremental_update_time: incremental_time,
        speedup_factor: speedup,
        number_of_attack_paths_initial: total_nodes,
        number_of_attack_paths_after_patch: total_nodes - 1,
    }
}

// Print a table of benchmark results suitable for a paper
pub fn print_benchmark_table(results: &[BenchmarkResults]) {
    println!("| Nodes | Initial (ms) | Incremental (us) | Speedup |");
    println!("|-------|--------------|------------------|---------|");
    for result in results {
        println!(
            "| {:>5} | {:>12.2} | {:>16.2} | {:>7.1}x |",
            result.number_of_nodes,
            result.initial_computation_time.as_secs_f64() * 1000.0,
            result.incremental_update_time.as_secs_f64() * 1_000_000.0,
            result.speedup_factor,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_generation() {
        let (network, vulns, positions, goals) = generate_chain_network(5);
        assert_eq!(network.len(), 4); // 4 edges for 5 nodes
        assert_eq!(vulns.len(), 5);
        assert_eq!(positions.len(), 1);
        assert_eq!(goals.len(), 1);
    }

    #[test]
    fn test_mesh_generation() {
        let (network, vulns, positions, goals) = generate_mesh_network(3, 3);
        // 3x3 grid has 9 nodes, 12 edges (6 horizontal + 6 vertical)
        assert_eq!(vulns.len(), 9);
        assert_eq!(network.len(), 12);
        assert_eq!(positions.len(), 1);
        assert_eq!(goals.len(), 1);
    }

    #[test]
    fn test_star_generation() {
        let (network, vulns, positions, goals) = generate_star_network(10);
        assert_eq!(network.len(), 10); // 10 edges from hub to leaves
        assert_eq!(vulns.len(), 11); // 10 leaves + 1 hub
        assert_eq!(positions.len(), 1);
        assert_eq!(goals.len(), 1);
    }
}
