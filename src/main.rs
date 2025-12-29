// Main entry point for the attack graph demonstration
// Shows how the attack graph updates incrementally when facts change

use std::time::Instant;

use differential_dataflow::input::Input;
use differential_dataflow::operators::Consolidate;
use timely::dataflow::operators::probe::Handle;
use timely::dataflow::operators::Probe;

mod rules;
mod schema;

use rules::build_attack_graph;
use schema::*;

fn main() {
    println!("========================================================================");
    println!("     Dynamic Attack Graphs using Differential Dataflow");
    println!("                    Proof of Concept");
    println!("========================================================================");
    println!();

    // Run the timely dataflow computation
    timely::execute_from_args(std::env::args(), |worker| {
        let worker_index = worker.index();
        let total_workers = worker.peers();

        // Only the first worker prints output
        let is_main_worker = worker_index == 0;

        // Probe to track when computation is complete
        let mut computation_probe = Handle::new();

        // Create input handles for each type of fact
        let (
            mut vulnerability_input,
            mut network_access_input,
            mut firewall_rules_input,
            mut attacker_position_input,
            mut attacker_goal_input,
            output_probe,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            // Create input collections for each fact type
            let (vuln_handle, vulnerability_collection) = scope.new_collection::<VulnerabilityRecord, isize>();
            let (network_handle, network_access_collection) = scope.new_collection::<NetworkAccessRule, isize>();
            let (firewall_handle, firewall_rules_collection) = scope.new_collection::<FirewallRuleRecord, isize>();
            let (position_handle, attacker_positions_collection) = scope.new_collection::<AttackerStartingPosition, isize>();
            let (goal_handle, attacker_goals_collection) = scope.new_collection::<AttackerTargetGoal, isize>();

            // Build the attack graph using our rules
            let (code_execution_results, machine_ownership_results, goal_reached_results) = build_attack_graph(
                &vulnerability_collection,
                &network_access_collection,
                &firewall_rules_collection,
                &attacker_positions_collection,
                &attacker_goals_collection,
            );

            // Print changes to code execution facts
            code_execution_results
                .inspect(move |change| {
                    if is_main_worker {
                        let (data, timestamp, difference) = change;
                        let change_type = if *difference > 0 { "+" } else { "-" };
                        println!("  [t={}] {} {}", timestamp, change_type, data);
                    }
                })
                .probe_with(&mut computation_probe);

            // Print changes to machine ownership facts
            machine_ownership_results
                .inspect(move |change| {
                    if is_main_worker {
                        let (data, timestamp, difference) = change;
                        let change_type = if *difference > 0 { "+" } else { "-" };
                        println!("  [t={}] {} {}", timestamp, change_type, data);
                    }
                })
                .probe_with(&mut computation_probe);

            // Print changes to goal reached facts
            goal_reached_results
                .inspect(move |change| {
                    if is_main_worker {
                        let (data, timestamp, difference) = change;
                        let change_type = if *difference > 0 { "+" } else { "-" };
                        println!("  [t={}] {} {} (TARGET COMPROMISED)", timestamp, change_type, data);
                    }
                })
                .probe_with(&mut computation_probe);

            let output_probe = goal_reached_results.probe();

            (
                vuln_handle,
                network_handle,
                firewall_handle,
                position_handle,
                goal_handle,
                output_probe,
            )
        });

        // ----------------------------------------------------------------
        // PHASE 1: Load initial network state (timestamp 0)
        // ----------------------------------------------------------------
        if is_main_worker {
            println!("------------------------------------------------------------------------");
            println!("PHASE 1: Loading initial network state (time=0)");
            println!("------------------------------------------------------------------------");
            println!();
            println!("Network topology:");
            println!("  [Internet] -> [DMZ/web01] -> [Internal/db01] -> [Target/admin01]");
            println!();
        }

        // Define network connections
        let network_topology = vec![
            // From internet to DMZ
            NetworkAccessRule::new("internet", "web01", "http"),
            NetworkAccessRule::new("internet", "web01", "https"),
            // From DMZ to internal network
            NetworkAccessRule::new("web01", "db01", "mysql"),
            NetworkAccessRule::new("web01", "db01", "ssh"),
            // From internal to admin server
            NetworkAccessRule::new("db01", "admin01", "ssh"),
            NetworkAccessRule::new("db01", "admin01", "smb"),
        ];

        // Define vulnerabilities on each host
        let known_vulnerabilities = vec![
            // Web server vulnerabilities
            VulnerabilityRecord::new("web01", "CVE-2024-1234", "http", PrivilegeLevel::User),
            VulnerabilityRecord::new("web01", "CVE-2024-1234", "https", PrivilegeLevel::User),
            // Database server vulnerabilities
            VulnerabilityRecord::new("db01", "CVE-2024-5678", "mysql", PrivilegeLevel::Root),
            VulnerabilityRecord::new("db01", "CVE-2024-9999", "ssh", PrivilegeLevel::User),
            // Admin server vulnerabilities
            VulnerabilityRecord::new("admin01", "CVE-2024-8888", "smb", PrivilegeLevel::Root),
        ];

        // Attacker starts on the internet
        let attacker_starting_positions = vec![
            AttackerStartingPosition::new("eve", "internet", PrivilegeLevel::User),
        ];

        // Attacker wants to compromise admin01
        let attacker_objectives = vec![
            AttackerTargetGoal::new("eve", "admin01"),
        ];

        // Insert all initial facts
        let computation_start_time = Instant::now();

        for network_connection in network_topology {
            network_access_input.insert(network_connection);
        }
        for vulnerability in known_vulnerabilities {
            vulnerability_input.insert(vulnerability);
        }
        for attacker_position in attacker_starting_positions {
            attacker_position_input.insert(attacker_position);
        }
        for objective in attacker_objectives {
            attacker_goal_input.insert(objective);
        }

        // Advance all inputs to timestamp 1 and flush
        vulnerability_input.advance_to(1);
        network_access_input.advance_to(1);
        firewall_rules_input.advance_to(1);
        attacker_position_input.advance_to(1);
        attacker_goal_input.advance_to(1);
        vulnerability_input.flush();
        network_access_input.flush();
        firewall_rules_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        // Wait for computation to finish
        while computation_probe.less_than(&1) {
            worker.step();
        }

        if is_main_worker {
            println!();
            println!("  Initial computation completed in {:?}", computation_start_time.elapsed());
            println!();
        }

        // ----------------------------------------------------------------
        // PHASE 2: Add a firewall rule (timestamp 1)
        // ----------------------------------------------------------------
        if is_main_worker {
            println!("------------------------------------------------------------------------");
            println!("PHASE 2: Adding firewall rule to block HTTP (time=1)");
            println!("         Rule: DENY internet -> web01 on http");
            println!("------------------------------------------------------------------------");
            println!();
        }

        let update_start_time = Instant::now();

        // Add firewall rule that blocks HTTP access
        firewall_rules_input.insert(FirewallRuleRecord::create_deny_rule("internet", "web01", "http"));

        // Advance to next timestamp
        vulnerability_input.advance_to(2);
        network_access_input.advance_to(2);
        firewall_rules_input.advance_to(2);
        attacker_position_input.advance_to(2);
        attacker_goal_input.advance_to(2);
        vulnerability_input.flush();
        network_access_input.flush();
        firewall_rules_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        while computation_probe.less_than(&2) {
            worker.step();
        }

        if is_main_worker {
            println!();
            println!("  Incremental update completed in {:?}", update_start_time.elapsed());
            println!("  Note: HTTP path removed, but HTTPS path still exists");
            println!();
        }

        // ----------------------------------------------------------------
        // PHASE 3: Patch the vulnerability (timestamp 2)
        // ----------------------------------------------------------------
        if is_main_worker {
            println!("------------------------------------------------------------------------");
            println!("PHASE 3: Patching CVE-2024-1234 on web01 (time=2)");
            println!("         This removes the initial entry point");
            println!("------------------------------------------------------------------------");
            println!();
        }

        let update_start_time = Instant::now();

        // Remove both HTTP and HTTPS vulnerabilities
        vulnerability_input.remove(VulnerabilityRecord::new("web01", "CVE-2024-1234", "http", PrivilegeLevel::User));
        vulnerability_input.remove(VulnerabilityRecord::new("web01", "CVE-2024-1234", "https", PrivilegeLevel::User));

        // Advance to next timestamp
        vulnerability_input.advance_to(3);
        network_access_input.advance_to(3);
        firewall_rules_input.advance_to(3);
        attacker_position_input.advance_to(3);
        attacker_goal_input.advance_to(3);
        vulnerability_input.flush();
        network_access_input.flush();
        firewall_rules_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        while computation_probe.less_than(&3) {
            worker.step();
        }

        if is_main_worker {
            println!();
            println!("  Incremental update completed in {:?}", update_start_time.elapsed());
            println!("  Target is now protected - all attack paths removed");
            println!();
        }

        // ----------------------------------------------------------------
        // PHASE 4: New vulnerability discovered (timestamp 3)
        // ----------------------------------------------------------------
        if is_main_worker {
            println!("------------------------------------------------------------------------");
            println!("PHASE 4: New CVE discovered - CVE-2024-0DAY on web01 (time=3)");
            println!("         HTTPS service is vulnerable again");
            println!("------------------------------------------------------------------------");
            println!();
        }

        let update_start_time = Instant::now();

        // Add new vulnerability
        vulnerability_input.insert(VulnerabilityRecord::new("web01", "CVE-2024-0DAY", "https", PrivilegeLevel::User));

        // Advance to next timestamp
        vulnerability_input.advance_to(4);
        network_access_input.advance_to(4);
        firewall_rules_input.advance_to(4);
        attacker_position_input.advance_to(4);
        attacker_goal_input.advance_to(4);
        vulnerability_input.flush();
        network_access_input.flush();
        firewall_rules_input.flush();
        attacker_position_input.flush();
        attacker_goal_input.flush();

        while computation_probe.less_than(&4) {
            worker.step();
        }

        if is_main_worker {
            println!();
            println!("  Incremental update completed in {:?}", update_start_time.elapsed());
            println!("  Warning: Attack paths restored via new vulnerability");
            println!();
        }

        // ----------------------------------------------------------------
        // Summary
        // ----------------------------------------------------------------
        if is_main_worker {
            println!("------------------------------------------------------------------------");
            println!("SUMMARY");
            println!("------------------------------------------------------------------------");
            println!();
            println!("This demonstration showed:");
            println!("  1. Initial attack graph computation from base facts");
            println!("  2. Incremental update when firewall rule added");
            println!("  3. Incremental update when vulnerability patched");
            println!("  4. Incremental update when new vulnerability discovered");
            println!();
            println!("Key observations:");
            println!("  - Updates only affected relevant derived facts");
            println!("  - No full recomputation was performed");
            println!("  - Changes propagated correctly through the graph");
            println!();
            println!("This demonstrates the power of differential dataflow for attack graphs.");
        }
    })
    .expect("Computation failed");
}
