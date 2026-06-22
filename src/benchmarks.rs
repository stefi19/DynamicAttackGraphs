// Benchmark module for measuring incremental vs full recomputation
// ----------------------------------------------------------------
// This module contains helper functions and small benchmarks that
// generate synthetic network topologies (chain, star, mesh) and run
// the dataflow to measure the wall-clock time for (a) computing the
// full attack graph from scratch and (b) performing a small
// incremental update (e.g. patching a vulnerability).  The
// measurements form the empirical evidence used in the paper.

use std::io::{self, Write};
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
    pub full_recomputation_after_update_time: Duration,
    pub speedup_factor: f64,
    pub incremental_vs_recompute_speedup: f64,
    // simple counts useful for debugging/plots
    pub number_of_attack_paths_initial: usize,
    pub number_of_attack_paths_after_patch: usize,
    pub derived_facts_before_update: usize,
    pub derived_facts_after_update: usize,
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
            "Full recomputation after update: {:?}",
            self.full_recomputation_after_update_time
        );
        println!(
            "Incremental vs recompute speedup: {:.2}x",
            self.incremental_vs_recompute_speedup
        );
        println!(
            "Attack paths (initial): {}",
            self.number_of_attack_paths_initial
        );
        println!(
            "Attack paths (after patch): {}",
            self.number_of_attack_paths_after_patch
        );
        println!(
            "Derived facts: {} before update, {} after update",
            self.derived_facts_before_update, self.derived_facts_after_update
        );
        println!();
    }
}

#[derive(Debug, Clone)]
pub struct BenchmarkCsvRow {
    pub benchmark_name: String,
    pub topology: String,
    pub number_of_nodes: usize,
    pub number_of_edges: usize,
    pub number_of_vulnerabilities: usize,
    pub update_type: String,
    pub initial_time_ms: f64,
    pub incremental_update_us: f64,
    pub full_recomputation_ms: f64,
    pub speedup: f64,
    pub derived_facts_before: usize,
    pub derived_facts_after: usize,
    pub changed_facts: Option<usize>,
    pub changed_base_facts: Option<usize>,
    pub changed_exec_code_facts: Option<usize>,
    pub changed_ownership_facts: Option<usize>,
    pub changed_goal_facts: Option<usize>,
    pub changed_derived_facts: Option<usize>,
    pub affected_hosts: Option<usize>,
}

impl BenchmarkCsvRow {
    pub fn from_star(number_of_leaves: usize, result: &BenchmarkResults) -> Self {
        Self::from_basic_result(
            "star_benchmark",
            "star",
            number_of_leaves + 1,
            number_of_leaves,
            number_of_leaves + 1,
            "patch_one_leaf_vulnerability",
            result,
        )
    }

    pub fn from_chain(result: &BenchmarkResults) -> Self {
        Self::from_basic_result(
            "chain_benchmark",
            "chain",
            result.number_of_nodes,
            result.number_of_nodes.saturating_sub(1),
            result.number_of_nodes,
            "patch_node_1_vulnerability",
            result,
        )
    }

    pub fn from_random_cut(number_of_nodes: usize, result: &RandomCutBenchmarkResults) -> Self {
        Self {
            benchmark_name: "chain_random_cut_benchmark".to_string(),
            topology: "chain_random_cut".to_string(),
            number_of_nodes,
            number_of_edges: number_of_nodes.saturating_sub(1),
            number_of_vulnerabilities: number_of_nodes,
            update_type: "random_vulnerability_cut_average".to_string(),
            initial_time_ms: duration_to_ms(result.initial_computation_time),
            incremental_update_us: duration_to_us(result.average_incremental_time),
            full_recomputation_ms: duration_to_ms(
                result.average_full_recomputation_after_update_time,
            ),
            speedup: result.average_incremental_vs_recompute_speedup,
            derived_facts_before: 0,
            derived_facts_after: 0,
            changed_facts: None,
            changed_base_facts: None,
            changed_exec_code_facts: None,
            changed_ownership_facts: None,
            changed_goal_facts: None,
            changed_derived_facts: None,
            affected_hosts: None,
        }
    }

    pub fn from_enterprise(result: &EnterpriseBenchmarkResults) -> Self {
        Self {
            benchmark_name: "enterprise_benchmark".to_string(),
            topology: "layered_enterprise".to_string(),
            number_of_nodes: result.number_of_nodes,
            number_of_edges: result.number_of_edges,
            number_of_vulnerabilities: result.number_of_vulnerabilities,
            update_type: result.update_pattern.label().to_string(),
            initial_time_ms: duration_to_ms(result.initial_computation_time),
            incremental_update_us: duration_to_us(result.incremental_update_time),
            full_recomputation_ms: duration_to_ms(result.full_recomputation_after_update_time),
            speedup: result.incremental_vs_recompute_speedup,
            derived_facts_before: result.derived_facts_before_update,
            derived_facts_after: result.derived_facts_after_update,
            changed_facts: Some(result.changed_derived_facts),
            changed_base_facts: Some(result.changed_base_facts),
            changed_exec_code_facts: None,
            changed_ownership_facts: None,
            changed_goal_facts: None,
            changed_derived_facts: Some(result.changed_derived_facts),
            affected_hosts: None,
        }
    }

    fn from_basic_result(
        benchmark_name: &str,
        topology: &str,
        number_of_nodes: usize,
        number_of_edges: usize,
        number_of_vulnerabilities: usize,
        update_type: &str,
        result: &BenchmarkResults,
    ) -> Self {
        Self {
            benchmark_name: benchmark_name.to_string(),
            topology: topology.to_string(),
            number_of_nodes,
            number_of_edges,
            number_of_vulnerabilities,
            update_type: update_type.to_string(),
            initial_time_ms: duration_to_ms(result.initial_computation_time),
            incremental_update_us: duration_to_us(result.incremental_update_time),
            full_recomputation_ms: duration_to_ms(result.full_recomputation_after_update_time),
            speedup: result.incremental_vs_recompute_speedup,
            derived_facts_before: result.derived_facts_before_update,
            derived_facts_after: result.derived_facts_after_update,
            changed_facts: Some(
                result
                    .derived_facts_before_update
                    .abs_diff(result.derived_facts_after_update),
            ),
            changed_base_facts: Some(1),
            changed_exec_code_facts: None,
            changed_ownership_facts: None,
            changed_goal_facts: None,
            changed_derived_facts: Some(
                result
                    .derived_facts_before_update
                    .abs_diff(result.derived_facts_after_update),
            ),
            affected_hosts: None,
        }
    }
}

pub fn write_benchmark_csv<W: Write>(writer: &mut W, rows: &[BenchmarkCsvRow]) -> io::Result<()> {
    writeln!(
        writer,
        "benchmark_name,topology,number_of_nodes,number_of_edges,number_of_vulnerabilities,update_type,initial_time_ms,incremental_update_us,full_recomputation_ms,speedup,derived_facts_before,derived_facts_after,changed_facts,changed_base_facts,changed_exec_code_facts,changed_ownership_facts,changed_goal_facts,changed_derived_facts,affected_hosts"
    )?;

    for row in rows {
        writeln!(
            writer,
            "{},{},{},{},{},{},{:.6},{:.6},{:.6},{:.6},{},{},{},{},{},{},{},{},{}",
            escape_csv_field(&row.benchmark_name),
            escape_csv_field(&row.topology),
            row.number_of_nodes,
            row.number_of_edges,
            row.number_of_vulnerabilities,
            escape_csv_field(&row.update_type),
            row.initial_time_ms,
            row.incremental_update_us,
            row.full_recomputation_ms,
            row.speedup,
            row.derived_facts_before,
            row.derived_facts_after,
            optional_usize(row.changed_facts),
            optional_usize(row.changed_base_facts),
            optional_usize(row.changed_exec_code_facts),
            optional_usize(row.changed_ownership_facts),
            optional_usize(row.changed_goal_facts),
            optional_usize(row.changed_derived_facts),
            optional_usize(row.affected_hosts)
        )?;
    }

    Ok(())
}

fn optional_usize(value: Option<usize>) -> String {
    value.map(|count| count.to_string()).unwrap_or_default()
}

fn duration_to_ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn duration_to_us(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000_000.0
}

fn escape_csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
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

#[derive(Debug, Clone)]
pub struct EnterpriseScenarioConfig {
    pub number_of_web_servers: usize,
    pub number_of_app_servers: usize,
    pub number_of_db_servers: usize,
    pub number_of_admin_servers: usize,
    pub vulnerability_density: f64,
    pub web_services: Vec<String>,
    pub app_services: Vec<String>,
    pub db_services: Vec<String>,
    pub admin_services: Vec<String>,
}

impl Default for EnterpriseScenarioConfig {
    fn default() -> Self {
        Self {
            number_of_web_servers: 8,
            number_of_app_servers: 6,
            number_of_db_servers: 3,
            number_of_admin_servers: 1,
            vulnerability_density: 0.75,
            web_services: vec!["https".to_string()],
            app_services: vec!["http".to_string()],
            db_services: vec!["postgres".to_string()],
            admin_services: vec!["smb".to_string()],
        }
    }
}

impl EnterpriseScenarioConfig {
    pub fn number_of_nodes(&self) -> usize {
        1 + self.number_of_web_servers
            + self.number_of_app_servers
            + self.number_of_db_servers
            + self.number_of_admin_servers
    }

    fn normalized_vulnerability_density(&self) -> f64 {
        self.vulnerability_density.clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone)]
pub struct EnterpriseScenario {
    pub network_access: Vec<NetworkAccessRule>,
    pub vulnerabilities: Vec<VulnerabilityRecord>,
    pub firewall_rules: Vec<FirewallRuleRecord>,
    pub attacker_positions: Vec<AttackerStartingPosition>,
    pub attacker_goals: Vec<AttackerTargetGoal>,
}

impl EnterpriseScenario {
    pub fn number_of_nodes(&self) -> usize {
        let mut hosts = std::collections::BTreeSet::new();

        for access in &self.network_access {
            hosts.insert(access.source_host.clone());
            hosts.insert(access.destination_host.clone());
        }
        for vulnerability in &self.vulnerabilities {
            hosts.insert(vulnerability.host_name.clone());
        }
        for position in &self.attacker_positions {
            hosts.insert(position.starting_host.clone());
        }
        for goal in &self.attacker_goals {
            hosts.insert(goal.target_host_name.clone());
        }

        hosts.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnterpriseUpdatePattern {
    PatchOneWebVulnerability,
    PatchOneAppVulnerability,
    AddDmzToAppFirewallDeny,
    BatchPatchTenPercent,
}

impl EnterpriseUpdatePattern {
    pub fn label(self) -> &'static str {
        match self {
            EnterpriseUpdatePattern::PatchOneWebVulnerability => "patch_one_web_vulnerability",
            EnterpriseUpdatePattern::PatchOneAppVulnerability => "patch_one_app_vulnerability",
            EnterpriseUpdatePattern::AddDmzToAppFirewallDeny => "add_dmz_to_app_firewall_deny",
            EnterpriseUpdatePattern::BatchPatchTenPercent => "batch_patch_10_percent",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnterpriseScenarioUpdate {
    pub pattern: EnterpriseUpdatePattern,
    pub updated_scenario: EnterpriseScenario,
    pub removed_vulnerabilities: Vec<VulnerabilityRecord>,
    pub added_firewall_rules: Vec<FirewallRuleRecord>,
}

impl EnterpriseScenarioUpdate {
    pub fn changed_base_fact_count(&self) -> usize {
        self.removed_vulnerabilities.len() + self.added_firewall_rules.len()
    }
}

pub fn generate_layered_enterprise_network(config: EnterpriseScenarioConfig) -> EnterpriseScenario {
    let web_hosts = layer_hosts("web", config.number_of_web_servers);
    let app_hosts = layer_hosts("app", config.number_of_app_servers);
    let db_hosts = layer_hosts("db", config.number_of_db_servers);
    let admin_hosts = layer_hosts("admin", config.number_of_admin_servers);

    let mut network_access = Vec::new();
    add_layer_edges(
        &mut network_access,
        &["internet".to_string()],
        &web_hosts,
        &config.web_services,
    );
    add_layer_edges(
        &mut network_access,
        &web_hosts,
        &app_hosts,
        &config.app_services,
    );
    add_layer_edges(
        &mut network_access,
        &app_hosts,
        &db_hosts,
        &config.db_services,
    );
    add_layer_edges(
        &mut network_access,
        &db_hosts,
        &admin_hosts,
        &config.admin_services,
    );

    let density = config.normalized_vulnerability_density();
    let mut vulnerabilities = Vec::new();
    add_layer_vulnerabilities(
        &mut vulnerabilities,
        "WEB",
        &web_hosts,
        &config.web_services,
        PrivilegeLevel::User,
        density,
    );
    add_layer_vulnerabilities(
        &mut vulnerabilities,
        "APP",
        &app_hosts,
        &config.app_services,
        PrivilegeLevel::User,
        density,
    );
    add_layer_vulnerabilities(
        &mut vulnerabilities,
        "DB",
        &db_hosts,
        &config.db_services,
        PrivilegeLevel::User,
        density,
    );
    add_layer_vulnerabilities(
        &mut vulnerabilities,
        "ADMIN",
        &admin_hosts,
        &config.admin_services,
        PrivilegeLevel::Root,
        density,
    );

    let attacker_positions = vec![AttackerStartingPosition::new(
        "attacker",
        "internet",
        PrivilegeLevel::User,
    )];
    let attacker_goals = vec![AttackerTargetGoal::new(
        "attacker",
        admin_hosts.first().map(String::as_str).unwrap_or("admin_0"),
    )];

    EnterpriseScenario {
        network_access,
        vulnerabilities,
        firewall_rules: Vec::new(),
        attacker_positions,
        attacker_goals,
    }
}

pub fn apply_enterprise_update_pattern(
    scenario: &EnterpriseScenario,
    pattern: EnterpriseUpdatePattern,
) -> EnterpriseScenarioUpdate {
    let mut updated_scenario = scenario.clone();
    let mut removed_vulnerabilities = Vec::new();
    let mut added_firewall_rules = Vec::new();

    match pattern {
        EnterpriseUpdatePattern::PatchOneWebVulnerability => {
            remove_first_vulnerability_with_prefix(
                &mut updated_scenario.vulnerabilities,
                "web_",
                &mut removed_vulnerabilities,
            );
        }
        EnterpriseUpdatePattern::PatchOneAppVulnerability => {
            remove_first_vulnerability_with_prefix(
                &mut updated_scenario.vulnerabilities,
                "app_",
                &mut removed_vulnerabilities,
            );
        }
        EnterpriseUpdatePattern::AddDmzToAppFirewallDeny => {
            if let Some(access) = scenario.network_access.iter().find(|access| {
                access.source_host.starts_with("web_")
                    && access.destination_host.starts_with("app_")
            }) {
                let rule = FirewallRuleRecord::create_deny_rule(
                    &access.source_host,
                    &access.destination_host,
                    &access.service_name,
                );
                updated_scenario.firewall_rules.push(rule.clone());
                added_firewall_rules.push(rule);
            }
        }
        EnterpriseUpdatePattern::BatchPatchTenPercent => {
            let patch_count = (updated_scenario.vulnerabilities.len() / 10).max(1);
            let patch_count = patch_count.min(updated_scenario.vulnerabilities.len());
            removed_vulnerabilities.extend(
                updated_scenario
                    .vulnerabilities
                    .drain(0..patch_count)
                    .collect::<Vec<_>>(),
            );
        }
    }

    EnterpriseScenarioUpdate {
        pattern,
        updated_scenario,
        removed_vulnerabilities,
        added_firewall_rules,
    }
}

fn remove_first_vulnerability_with_prefix(
    vulnerabilities: &mut Vec<VulnerabilityRecord>,
    host_prefix: &str,
    removed_vulnerabilities: &mut Vec<VulnerabilityRecord>,
) {
    if let Some(index) = vulnerabilities
        .iter()
        .position(|vulnerability| vulnerability.host_name.starts_with(host_prefix))
    {
        removed_vulnerabilities.push(vulnerabilities.remove(index));
    }
}

fn layer_hosts(layer_name: &str, count: usize) -> Vec<String> {
    (0..count)
        .map(|index| format!("{layer_name}_{index}"))
        .collect()
}

fn add_layer_edges(
    network_access: &mut Vec<NetworkAccessRule>,
    sources: &[String],
    destinations: &[String],
    services: &[String],
) {
    for source in sources {
        for destination in destinations {
            for service in services {
                network_access.push(NetworkAccessRule::new(source, destination, service));
            }
        }
    }
}

fn add_layer_vulnerabilities(
    vulnerabilities: &mut Vec<VulnerabilityRecord>,
    layer_label: &str,
    hosts: &[String],
    services: &[String],
    privilege: PrivilegeLevel,
    density: f64,
) {
    for (host_index, host) in hosts.iter().enumerate() {
        for (service_index, service) in services.iter().enumerate() {
            if should_include_enterprise_vulnerability(host_index, service_index, density) {
                vulnerabilities.push(VulnerabilityRecord::new(
                    host,
                    &format!("CVE-ENTERPRISE-{layer_label}-{host_index}-{service_index}"),
                    service,
                    privilege.clone(),
                ));
            }
        }
    }
}

fn should_include_enterprise_vulnerability(
    host_index: usize,
    service_index: usize,
    density: f64,
) -> bool {
    if density <= 0.0 {
        return host_index == 0 && service_index == 0;
    }
    if density >= 1.0 || (host_index == 0 && service_index == 0) {
        return true;
    }

    let deterministic_score = ((host_index * 37 + service_index * 17 + 11) % 100) as f64 / 100.0;
    deterministic_score < density
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

fn vulnerability_matches(
    vulnerability: &VulnerabilityRecord,
    host_name: &str,
    vulnerability_id: &str,
    affected_service: &str,
    privilege_gained_on_exploit: PrivilegeLevel,
) -> bool {
    vulnerability.host_name == host_name
        && vulnerability.vulnerability_id == vulnerability_id
        && vulnerability.affected_service == affected_service
        && vulnerability.privilege_gained_on_exploit == privilege_gained_on_exploit
}

// Run the chain benchmark: measure initial build time and the time
// to perform a single incremental patch (remove vulnerability at
// node_1).  The timings are returned in a `BenchmarkResults` struct.
pub fn run_chain_benchmark(number_of_nodes: usize) -> BenchmarkResults {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let (network_topology, vulnerabilities, attacker_positions, attacker_goals) =
        generate_chain_network(number_of_nodes);
    let firewall_rules: Vec<FirewallRuleRecord> = Vec::new();

    let initial_recomputation = measure_full_recomputation(
        &network_topology,
        &vulnerabilities,
        &firewall_rules,
        &attacker_positions,
        &attacker_goals,
    );
    let vulnerabilities_after_patch: Vec<_> = vulnerabilities
        .iter()
        .filter(|vulnerability| {
            !vulnerability_matches(
                vulnerability,
                "node_1",
                "CVE-CHAIN-1",
                "ssh",
                PrivilegeLevel::Root,
            )
        })
        .cloned()
        .collect();
    let recomputation_after_update = measure_full_recomputation(
        &network_topology,
        &vulnerabilities_after_patch,
        &firewall_rules,
        &attacker_positions,
        &attacker_goals,
    );

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
    let incremental_vs_recompute_speedup = if incremental_time.as_nanos() > 0 {
        recomputation_after_update.computation_time.as_secs_f64() / incremental_time.as_secs_f64()
    } else {
        f64::INFINITY
    };

    BenchmarkResults {
        number_of_nodes,
        initial_computation_time: initial_time,
        incremental_update_time: incremental_time,
        full_recomputation_after_update_time: recomputation_after_update.computation_time,
        speedup_factor: speedup,
        incremental_vs_recompute_speedup,
        number_of_attack_paths_initial: number_of_nodes,
        number_of_attack_paths_after_patch: 1,
        derived_facts_before_update: initial_recomputation.derived_fact_count,
        derived_facts_after_update: recomputation_after_update.derived_fact_count,
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
    pub average_full_recomputation_after_update_time: Duration,
    pub min_incremental_time: Duration,
    pub max_incremental_time: Duration,
    pub average_speedup: f64,
    pub average_incremental_vs_recompute_speedup: f64,
}

#[derive(Debug, Clone)]
pub struct EnterpriseBenchmarkResults {
    pub update_pattern: EnterpriseUpdatePattern,
    pub number_of_nodes: usize,
    pub number_of_edges: usize,
    pub number_of_vulnerabilities: usize,
    pub changed_base_facts: usize,
    pub initial_computation_time: Duration,
    pub incremental_update_time: Duration,
    pub full_recomputation_after_update_time: Duration,
    pub incremental_vs_recompute_speedup: f64,
    pub derived_facts_before_update: usize,
    pub derived_facts_after_update: usize,
    pub changed_derived_facts: usize,
}

impl EnterpriseBenchmarkResults {
    pub fn print_summary(&self) {
        println!("=== ENTERPRISE BENCHMARK RESULT ===");
        println!("Update pattern: {}", self.update_pattern.label());
        println!("Nodes: {}", self.number_of_nodes);
        println!("Network edges: {}", self.number_of_edges);
        println!("Vulnerabilities: {}", self.number_of_vulnerabilities);
        println!("Changed base facts: {}", self.changed_base_facts);
        println!("Initial computation: {:?}", self.initial_computation_time);
        println!("Incremental update:  {:?}", self.incremental_update_time);
        println!(
            "Full recomputation after update: {:?}",
            self.full_recomputation_after_update_time
        );
        println!(
            "Incremental vs recompute speedup: {:.2}x",
            self.incremental_vs_recompute_speedup
        );
        println!(
            "Derived facts: {} before update, {} after update",
            self.derived_facts_before_update, self.derived_facts_after_update
        );
        println!("Changed derived fact count: {}", self.changed_derived_facts);
        println!();
    }
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

    let mut rng = rand::thread_rng();
    let cut_positions: Vec<usize> = (0..iterations)
        .map(|_| rng.gen_range(0..number_of_nodes))
        .collect();

    // Storage for timing data across iterations
    let initial_nanos = Arc::new(AtomicU64::new(0));
    let incremental_times_nanos = Arc::new(std::sync::Mutex::new(Vec::new()));
    let initial_clone = Arc::clone(&initial_nanos);
    let times_clone = Arc::clone(&incremental_times_nanos);

    let iterations_count = iterations;
    let dataflow_network_topology = network_topology.clone();
    let dataflow_vulnerabilities = vulnerabilities.clone();
    let dataflow_attacker_positions = attacker_positions.clone();
    let dataflow_attacker_goals = attacker_goals.clone();
    let dataflow_cut_positions = cut_positions.clone();

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

        for network_rule in &dataflow_network_topology {
            network_input.insert(network_rule.clone());
        }
        for vulnerability in &dataflow_vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for position in &dataflow_attacker_positions {
            attacker_position_input.insert(position.clone());
        }
        for goal in &dataflow_attacker_goals {
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
        let mut times_vec = times_clone.lock().unwrap();

        for i in 0..iterations_count {
            let time_step = 2 + (i * 2); // Each iteration uses 2 time steps

            // Use the same sampled cuts for incremental and recompute timing.
            let k = dataflow_cut_positions[i];
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
    let firewall_rules: Vec<FirewallRuleRecord> = Vec::new();
    let recomputation_times_nanos: Vec<u64> = cut_positions
        .iter()
        .map(|k| {
            let patched_vulnerabilities: Vec<_> = vulnerabilities
                .iter()
                .filter(|vulnerability| {
                    !vulnerability_matches(
                        vulnerability,
                        &format!("node_{}", k),
                        &format!("CVE-CHAIN-{}", k),
                        "ssh",
                        PrivilegeLevel::Root,
                    )
                })
                .cloned()
                .collect();

            measure_full_recomputation(
                &network_topology,
                &patched_vulnerabilities,
                &firewall_rules,
                &attacker_positions,
                &attacker_goals,
            )
            .computation_time
            .as_nanos() as u64
        })
        .collect();

    let min_nanos = *times.iter().min().unwrap_or(&0);
    let max_nanos = *times.iter().max().unwrap_or(&0);
    let avg_nanos = if times.is_empty() {
        0
    } else {
        times.iter().sum::<u64>() / times.len() as u64
    };

    let avg_incremental = Duration::from_nanos(avg_nanos);
    let avg_recompute_nanos = if recomputation_times_nanos.is_empty() {
        0
    } else {
        recomputation_times_nanos.iter().sum::<u64>() / recomputation_times_nanos.len() as u64
    };
    let avg_recompute = Duration::from_nanos(avg_recompute_nanos);
    let average_speedup = if avg_nanos > 0 {
        initial_time.as_secs_f64() / avg_incremental.as_secs_f64()
    } else {
        f64::INFINITY
    };
    let average_incremental_vs_recompute_speedup = if avg_nanos > 0 {
        avg_recompute.as_secs_f64() / avg_incremental.as_secs_f64()
    } else {
        f64::INFINITY
    };

    RandomCutBenchmarkResults {
        number_of_nodes,
        number_of_iterations: iterations,
        initial_computation_time: initial_time,
        average_incremental_time: avg_incremental,
        average_full_recomputation_after_update_time: avg_recompute,
        min_incremental_time: Duration::from_nanos(min_nanos),
        max_incremental_time: Duration::from_nanos(max_nanos),
        average_speedup,
        average_incremental_vs_recompute_speedup,
    }
}

pub fn run_enterprise_benchmark(
    config: EnterpriseScenarioConfig,
) -> Vec<EnterpriseBenchmarkResults> {
    let scenario = generate_layered_enterprise_network(config);
    let update_patterns = [
        EnterpriseUpdatePattern::PatchOneWebVulnerability,
        EnterpriseUpdatePattern::PatchOneAppVulnerability,
        EnterpriseUpdatePattern::AddDmzToAppFirewallDeny,
        EnterpriseUpdatePattern::BatchPatchTenPercent,
    ];

    update_patterns
        .into_iter()
        .map(|pattern| run_enterprise_benchmark_for_update(&scenario, pattern))
        .collect()
}

pub fn run_enterprise_benchmark_for_update(
    scenario: &EnterpriseScenario,
    pattern: EnterpriseUpdatePattern,
) -> EnterpriseBenchmarkResults {
    let update = apply_enterprise_update_pattern(scenario, pattern);
    let initial_recomputation = measure_full_recomputation(
        &scenario.network_access,
        &scenario.vulnerabilities,
        &scenario.firewall_rules,
        &scenario.attacker_positions,
        &scenario.attacker_goals,
    );
    let recomputation_after_update = measure_full_recomputation(
        &update.updated_scenario.network_access,
        &update.updated_scenario.vulnerabilities,
        &update.updated_scenario.firewall_rules,
        &update.updated_scenario.attacker_positions,
        &update.updated_scenario.attacker_goals,
    );

    let (initial_computation_time, incremental_update_time) =
        measure_enterprise_incremental_update(scenario, &update);
    let incremental_vs_recompute_speedup = if incremental_update_time.as_nanos() > 0 {
        recomputation_after_update.computation_time.as_secs_f64()
            / incremental_update_time.as_secs_f64()
    } else {
        f64::INFINITY
    };

    EnterpriseBenchmarkResults {
        update_pattern: pattern,
        number_of_nodes: scenario.number_of_nodes(),
        number_of_edges: scenario.network_access.len(),
        number_of_vulnerabilities: scenario.vulnerabilities.len(),
        changed_base_facts: update.changed_base_fact_count(),
        initial_computation_time,
        incremental_update_time,
        full_recomputation_after_update_time: recomputation_after_update.computation_time,
        incremental_vs_recompute_speedup,
        derived_facts_before_update: initial_recomputation.derived_fact_count,
        derived_facts_after_update: recomputation_after_update.derived_fact_count,
        changed_derived_facts: initial_recomputation
            .derived_fact_count
            .abs_diff(recomputation_after_update.derived_fact_count),
    }
}

fn measure_enterprise_incremental_update(
    scenario: &EnterpriseScenario,
    update: &EnterpriseScenarioUpdate,
) -> (Duration, Duration) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    let scenario = scenario.clone();
    let removed_vulnerabilities = update.removed_vulnerabilities.clone();
    let added_firewall_rules = update.added_firewall_rules.clone();
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

        let start_initial = Instant::now();

        for network_rule in &scenario.network_access {
            network_input.insert(network_rule.clone());
        }
        for vulnerability in &scenario.vulnerabilities {
            vulnerability_input.insert(vulnerability.clone());
        }
        for firewall_rule in &scenario.firewall_rules {
            firewall_input.insert(firewall_rule.clone());
        }
        for position in &scenario.attacker_positions {
            attacker_position_input.insert(position.clone());
        }
        for goal in &scenario.attacker_goals {
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
        let start_incremental = Instant::now();

        for vulnerability in &removed_vulnerabilities {
            vulnerability_input.remove(vulnerability.clone());
        }
        for firewall_rule in &added_firewall_rules {
            firewall_input.insert(firewall_rule.clone());
        }

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

    (
        Duration::from_nanos(initial_nanos.load(Ordering::SeqCst)),
        Duration::from_nanos(incremental_nanos.load(Ordering::SeqCst)),
    )
}

// Print results table for random cut benchmark
pub fn print_random_cut_benchmark_table(results: &[RandomCutBenchmarkResults]) {
    println!(
        "| Nodes | Iterations | Initial (ms) | Avg Incr (us) | Avg Recompute (ms) | Min (us) | Max (us) | Avg Speedup | Recompute Speedup |"
    );
    println!(
        "|-------|------------|--------------|---------------|--------------------|----------|----------|-------------|-------------------|"
    );
    for result in results {
        println!(
            "| {:>5} | {:>10} | {:>12.2} | {:>13.2} | {:>18.2} | {:>8.2} | {:>8.2} | {:>11.1}x | {:>17.1}x |",
            result.number_of_nodes,
            result.number_of_iterations,
            result.initial_computation_time.as_secs_f64() * 1000.0,
            result.average_incremental_time.as_secs_f64() * 1_000_000.0,
            result
                .average_full_recomputation_after_update_time
                .as_secs_f64()
                * 1000.0,
            result.min_incremental_time.as_secs_f64() * 1_000_000.0,
            result.max_incremental_time.as_secs_f64() * 1_000_000.0,
            result.average_speedup,
            result.average_incremental_vs_recompute_speedup,
        );
    }
}

pub fn print_enterprise_benchmark_table(results: &[EnterpriseBenchmarkResults]) {
    println!(
        "| Update | Nodes | Edges | Vulns | Changed Base | Initial (ms) | Incremental (us) | Recompute (ms) | Recompute Speedup | Facts Before | Facts After | Changed Facts |"
    );
    println!(
        "|--------|------:|------:|------:|-------------:|-------------:|-----------------:|---------------:|------------------:|-------------:|------------:|--------------:|"
    );
    for result in results {
        println!(
            "| {} | {:>5} | {:>5} | {:>5} | {:>12} | {:>12.2} | {:>16.2} | {:>14.2} | {:>17.1}x | {:>12} | {:>11} | {:>13} |",
            result.update_pattern.label(),
            result.number_of_nodes,
            result.number_of_edges,
            result.number_of_vulnerabilities,
            result.changed_base_facts,
            result.initial_computation_time.as_secs_f64() * 1000.0,
            result.incremental_update_time.as_secs_f64() * 1_000_000.0,
            result.full_recomputation_after_update_time.as_secs_f64() * 1000.0,
            result.incremental_vs_recompute_speedup,
            result.derived_facts_before_update,
            result.derived_facts_after_update,
            result.changed_derived_facts,
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
    let firewall_rules: Vec<FirewallRuleRecord> = Vec::new();

    let initial_recomputation = measure_full_recomputation(
        &network_topology,
        &vulnerabilities,
        &firewall_rules,
        &attacker_positions,
        &attacker_goals,
    );
    let vulnerabilities_after_patch: Vec<_> = vulnerabilities
        .iter()
        .filter(|vulnerability| {
            !vulnerability_matches(
                vulnerability,
                "leaf_0",
                "CVE-LEAF-0",
                "ssh",
                PrivilegeLevel::Root,
            )
        })
        .cloned()
        .collect();
    let recomputation_after_update = measure_full_recomputation(
        &network_topology,
        &vulnerabilities_after_patch,
        &firewall_rules,
        &attacker_positions,
        &attacker_goals,
    );

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
    let incremental_vs_recompute_speedup = if incremental_time.as_nanos() > 0 {
        recomputation_after_update.computation_time.as_secs_f64() / incremental_time.as_secs_f64()
    } else {
        f64::INFINITY
    };

    BenchmarkResults {
        number_of_nodes: total_nodes,
        initial_computation_time: initial_time,
        incremental_update_time: incremental_time,
        full_recomputation_after_update_time: recomputation_after_update.computation_time,
        speedup_factor: speedup,
        incremental_vs_recompute_speedup,
        number_of_attack_paths_initial: total_nodes,
        number_of_attack_paths_after_patch: total_nodes - 1,
        derived_facts_before_update: initial_recomputation.derived_fact_count,
        derived_facts_after_update: recomputation_after_update.derived_fact_count,
    }
}

// Print a table of benchmark results suitable for a paper
pub fn print_benchmark_table(results: &[BenchmarkResults]) {
    println!(
        "| Nodes | Initial (ms) | Incremental (us) | Recompute After Update (ms) | Initial Speedup | Recompute Speedup | Facts Before | Facts After |"
    );
    println!(
        "|-------|--------------|------------------|-----------------------------|-----------------|-------------------|--------------|-------------|"
    );
    for result in results {
        println!(
            "| {:>5} | {:>12.2} | {:>16.2} | {:>27.2} | {:>15.1}x | {:>17.1}x | {:>12} | {:>11} |",
            result.number_of_nodes,
            result.initial_computation_time.as_secs_f64() * 1000.0,
            result.incremental_update_time.as_secs_f64() * 1_000_000.0,
            result.full_recomputation_after_update_time.as_secs_f64() * 1000.0,
            result.speedup_factor,
            result.incremental_vs_recompute_speedup,
            result.derived_facts_before_update,
            result.derived_facts_after_update,
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

    #[test]
    fn test_layered_enterprise_generation() {
        let config = EnterpriseScenarioConfig {
            number_of_web_servers: 2,
            number_of_app_servers: 3,
            number_of_db_servers: 2,
            number_of_admin_servers: 1,
            vulnerability_density: 1.0,
            web_services: vec!["https".to_string(), "http".to_string()],
            app_services: vec!["api".to_string()],
            db_services: vec!["postgres".to_string()],
            admin_services: vec!["smb".to_string()],
        };

        let scenario = generate_layered_enterprise_network(config);

        assert_eq!(scenario.number_of_nodes(), 9);
        assert_eq!(scenario.network_access.len(), 4 + 6 + 6 + 2);
        assert_eq!(scenario.vulnerabilities.len(), 4 + 3 + 2 + 1);
        assert_eq!(scenario.firewall_rules.len(), 0);
        assert_eq!(scenario.attacker_positions.len(), 1);
        assert_eq!(scenario.attacker_positions[0].starting_host, "internet");
        assert_eq!(scenario.attacker_goals.len(), 1);
        assert_eq!(scenario.attacker_goals[0].target_host_name, "admin_0");
    }

    #[test]
    fn test_layered_enterprise_generation_keeps_one_path_at_zero_density() {
        let scenario = generate_layered_enterprise_network(EnterpriseScenarioConfig {
            vulnerability_density: 0.0,
            ..EnterpriseScenarioConfig::default()
        });

        assert!(scenario
            .vulnerabilities
            .iter()
            .any(|vulnerability| vulnerability.host_name == "web_0"));
        assert!(scenario
            .vulnerabilities
            .iter()
            .any(|vulnerability| vulnerability.host_name == "app_0"));
        assert!(scenario
            .vulnerabilities
            .iter()
            .any(|vulnerability| vulnerability.host_name == "db_0"));
        assert!(scenario
            .vulnerabilities
            .iter()
            .any(|vulnerability| vulnerability.host_name == "admin_0"));
    }

    #[test]
    fn test_enterprise_patch_one_web_vulnerability_update() {
        let scenario = generate_layered_enterprise_network(EnterpriseScenarioConfig::default());
        let update = apply_enterprise_update_pattern(
            &scenario,
            EnterpriseUpdatePattern::PatchOneWebVulnerability,
        );

        assert_eq!(
            update.pattern,
            EnterpriseUpdatePattern::PatchOneWebVulnerability
        );
        assert_eq!(update.removed_vulnerabilities.len(), 1);
        assert!(update.removed_vulnerabilities[0]
            .host_name
            .starts_with("web_"));
        assert_eq!(
            update.updated_scenario.vulnerabilities.len(),
            scenario.vulnerabilities.len() - 1
        );
        assert_eq!(update.changed_base_fact_count(), 1);
    }

    #[test]
    fn test_enterprise_firewall_deny_update() {
        let scenario = generate_layered_enterprise_network(EnterpriseScenarioConfig::default());
        let update = apply_enterprise_update_pattern(
            &scenario,
            EnterpriseUpdatePattern::AddDmzToAppFirewallDeny,
        );

        assert_eq!(update.removed_vulnerabilities.len(), 0);
        assert_eq!(update.added_firewall_rules.len(), 1);
        assert!(update.added_firewall_rules[0]
            .source_zone
            .starts_with("web_"));
        assert!(update.added_firewall_rules[0]
            .destination_host
            .starts_with("app_"));
        assert_eq!(update.updated_scenario.firewall_rules.len(), 1);
        assert_eq!(update.changed_base_fact_count(), 1);
    }

    #[test]
    fn test_enterprise_batch_patch_update() {
        let scenario = generate_layered_enterprise_network(EnterpriseScenarioConfig {
            vulnerability_density: 1.0,
            ..EnterpriseScenarioConfig::default()
        });
        let update = apply_enterprise_update_pattern(
            &scenario,
            EnterpriseUpdatePattern::BatchPatchTenPercent,
        );
        let expected_patch_count = (scenario.vulnerabilities.len() / 10).max(1);

        assert_eq!(update.removed_vulnerabilities.len(), expected_patch_count);
        assert_eq!(
            update.updated_scenario.vulnerabilities.len(),
            scenario.vulnerabilities.len() - expected_patch_count
        );
        assert_eq!(update.changed_base_fact_count(), expected_patch_count);
    }

    #[test]
    fn test_benchmark_csv_writer_outputs_header_and_rows() {
        let rows = vec![BenchmarkCsvRow {
            benchmark_name: "example,benchmark".to_string(),
            topology: "chain".to_string(),
            number_of_nodes: 3,
            number_of_edges: 2,
            number_of_vulnerabilities: 3,
            update_type: "patch".to_string(),
            initial_time_ms: 1.25,
            incremental_update_us: 42.0,
            full_recomputation_ms: 1.0,
            speedup: 23.8,
            derived_facts_before: 9,
            derived_facts_after: 4,
            changed_facts: Some(5),
            changed_base_facts: Some(1),
            changed_exec_code_facts: None,
            changed_ownership_facts: None,
            changed_goal_facts: None,
            changed_derived_facts: Some(5),
            affected_hosts: None,
        }];
        let mut output = Vec::new();

        write_benchmark_csv(&mut output, &rows).unwrap();
        let csv = String::from_utf8(output).unwrap();

        assert!(csv.starts_with("benchmark_name,topology,number_of_nodes"));
        assert!(csv.contains("\"example,benchmark\",chain,3,2,3,patch"));
        assert!(csv.contains(",9,4,5,1,,,,5,\n"));
    }
}
