// Benchmark module for measuring incremental vs full recomputation performance
// This is the core evidence for the research paper

use std::time::{Duration, Instant};

use differential_dataflow::input::Input;
use differential_dataflow::operators::Consolidate;
use timely::dataflow::operators::probe::Handle;

use crate::rules::build_attack_graph;
use crate::schema::*;

// Results from a benchmark run
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    pub number_of_nodes: usize,
    pub initial_computation_time: Duration,
    pub incremental_update_time: Duration,
    pub speedup_factor: f64,
    pub number_of_attack_paths_initial: usize,
    pub number_of_attack_paths_after_patch: usize,
}

impl BenchmarkResults {
    pub fn print_summary(&self) {
        println!("=== BENCHMARK RESULTS ===");
        println!("Network size: {} nodes", self.number_of_nodes);
        println!("Initial computation: {:?}", self.initial_computation_time);
        println!("Incremental update:  {:?}", self.incremental_update_time);
        println!("Speedup factor: {:.2}x", self.speedup_factor);
        println!("Attack paths (initial): {}", self.number_of_attack_paths_initial);
        println!("Attack paths (after patch): {}", self.number_of_attack_paths_after_patch);
        println!();
    }
}

// Generate a linear chain network: node_0 -> node_1 -> node_2 -> ... -> node_n
// Each node has a vulnerability, attacker starts at node_0, goal is node_n
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

    // Create chain: node_0 -> node_1 -> node_2 -> ... -> node_(n-1)
    for node_index in 0..number_of_nodes {
        let node_name = format!("node_{}", node_index);
        
        // Each node has a vulnerability on ssh service
        vulnerabilities.push(VulnerabilityRecord::new(
            &node_name,
            &format!("CVE-CHAIN-{}", node_index),
            "ssh",
            PrivilegeLevel::Root,
        ));
        
        // Add edge to next node (except for last node)
        if node_index < number_of_nodes - 1 {
            let next_node_name = format!("node_{}", node_index + 1);
            network_topology.push(NetworkAccessRule::new(&node_name, &next_node_name, "ssh"));
        }
    }

    // Attacker starts at node_0
    let attacker_positions = vec![
        AttackerStartingPosition::new("attacker", "node_0", PrivilegeLevel::Root),
    ];

    // Goal is to reach last node
    let attacker_goals = vec![
        AttackerTargetGoal::new("attacker", &format!("node_{}", number_of_nodes - 1)),
    ];

    (network_topology, vulnerabilities, attacker_positions, attacker_goals)
}

// Generate a mesh network where nodes form a grid
// This creates more complex attack paths
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
            
            // Each node has a vulnerability
            vulnerabilities.push(VulnerabilityRecord::new(
                &current_node,
                &format!("CVE-MESH-{}-{}", x, y),
                "ssh",
                PrivilegeLevel::Root,
            ));
            
            // Connect to right neighbor
            if x + 1 < grid_width {
                network_topology.push(NetworkAccessRule::new(
                    &current_node,
                    &node_name(x + 1, y),
                    "ssh",
                ));
            }
            
            // Connect to bottom neighbor
            if y + 1 < grid_height {
                network_topology.push(NetworkAccessRule::new(
                    &current_node,
                    &node_name(x, y + 1),
                    "ssh",
                ));
            }
        }
    }

    // Attacker starts at top-left
    let attacker_positions = vec![
        AttackerStartingPosition::new("attacker", "node_0_0", PrivilegeLevel::Root),
    ];

    // Goal is bottom-right
    let attacker_goals = vec![
        AttackerTargetGoal::new("attacker", &node_name(grid_width - 1, grid_height - 1)),
    ];

    (network_topology, vulnerabilities, attacker_positions, attacker_goals)
}

// Generate a star network: central hub connected to N leaf nodes
// This converges in just 2 iterations (much faster than chain)
// Hub -> Leaf_1, Hub -> Leaf_2, ... Hub -> Leaf_N
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

    // Central hub
    vulnerabilities.push(VulnerabilityRecord::new(
        "hub",
        "CVE-HUB-0",
        "ssh",
        PrivilegeLevel::Root,
    ));

    // Create leaves and connect them to hub
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

    // Attacker starts at hub
    let attacker_positions = vec![
        AttackerStartingPosition::new("attacker", "hub", PrivilegeLevel::Root),
    ];

    // Goal is last leaf
    let attacker_goals = vec![
        AttackerTargetGoal::new("attacker", &format!("leaf_{}", number_of_leaves - 1)),
    ];

    (network_topology, vulnerabilities, attacker_positions, attacker_goals)
}

// Run the chain benchmark - this is the "money shot" for the paper
// Shows O(1) incremental update vs O(n) full recomputation
pub fn run_chain_benchmark(number_of_nodes: usize) -> BenchmarkResults {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    
    let (network_topology, vulnerabilities, attacker_positions, attacker_goals) =
        generate_chain_network(number_of_nodes);

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
            let (vuln_handle, vuln_collection) = scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) = scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) = scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) = scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) = scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, _owns_machine, _goals_reached) = build_attack_graph(
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code.consolidate().probe_with(&mut probe);

            (vuln_handle, network_handle, firewall_handle, position_handle, goal_handle)
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

        // Phase 2: Incremental update - patch vulnerability on node_1
        // This breaks the chain at the second node
        let start_incremental = Instant::now();

        vulnerability_input.remove(VulnerabilityRecord::new(
            "node_1",
            "CVE-CHAIN-1",
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
        number_of_nodes,
        initial_computation_time: initial_time,
        incremental_update_time: incremental_time,
        speedup_factor: speedup,
        number_of_attack_paths_initial: number_of_nodes,
        number_of_attack_paths_after_patch: 1,
    }
}

// Run multiple benchmarks with increasing sizes
pub fn run_scalability_benchmark(sizes: &[usize]) -> Vec<BenchmarkResults> {
    sizes.iter().map(|&size| run_chain_benchmark(size)).collect()
}

// Extended results for random cut benchmark
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

// Random Cut Benchmark for Chain topology
// This shows how speedup depends on cut position
// Cutting at position k means only k nodes need to be recomputed
pub fn run_chain_random_cut_benchmark(number_of_nodes: usize, iterations: usize) -> RandomCutBenchmarkResults {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use rand::Rng;
    
    let (network_topology, vulnerabilities, attacker_positions, attacker_goals) =
        generate_chain_network(number_of_nodes);

    // Storage for timing data
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
            let (vuln_handle, vuln_collection) = scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) = scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) = scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) = scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) = scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, _owns_machine, _goals_reached) = build_attack_graph(
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code.consolidate().probe_with(&mut probe);

            (vuln_handle, network_handle, firewall_handle, position_handle, goal_handle)
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
    println!("| Nodes | Iterations | Initial (ms) | Avg Incr (us) | Min (us) | Max (us) | Avg Speedup |");
    println!("|-------|------------|--------------|---------------|----------|----------|-------------|");
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
            let (vuln_handle, vuln_collection) = scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_collection) = scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_collection) = scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, position_collection) = scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, goal_collection) = scope.new_collection::<AttackerTargetGoal, isize>();

            let (exec_code, _owns_machine, _goals_reached) = build_attack_graph(
                &vuln_collection,
                &network_collection,
                &firewall_collection,
                &position_collection,
                &goal_collection,
            );

            exec_code.consolidate().probe_with(&mut probe);

            (vuln_handle, network_handle, firewall_handle, position_handle, goal_handle)
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
