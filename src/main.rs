//! Main entry point for the Dynamic Attack Graph PoC
//!
//! This demonstrates:
//! 1. Building the attack graph from initial facts
//! 2. Incrementally updating when facts change
//! 3. Observing the differential (incremental) output

use std::time::Instant;

use differential_dataflow::input::Input;
use differential_dataflow::operators::arrange::ArrangeByKey;
use differential_dataflow::operators::Consolidate;
use timely::dataflow::operators::probe::Handle;
use timely::dataflow::operators::Probe;

mod rules;
mod schema;

use rules::build_attack_graph;
use schema::*;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║     Dynamic Attack Graphs using Differential Dataflow            ║");
    println!("║                    Proof of Concept                              ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();

    // Run the timely dataflow computation
    timely::execute_from_args(std::env::args(), |worker| {
        let index = worker.index();
        let peers = worker.peers();

        // Only worker 0 prints detailed output
        let is_main = index == 0;

        // Create a probe to track computation progress
        let mut probe = Handle::new();

        // Create input handles for each fact type
        let (
            mut vuln_input,
            mut network_input,
            mut firewall_input,
            mut attacker_loc_input,
            mut attacker_goal_input,
            probe_handle,
        ) = worker.dataflow::<usize, _, _>(|scope| {
            // Create input collections
            let (vuln_handle, vulnerabilities) = scope.new_collection::<Vulnerability, isize>();
            let (net_handle, network_access) = scope.new_collection::<NetworkAccess, isize>();
            let (fw_handle, firewall_rules) = scope.new_collection::<FirewallRule, isize>();
            let (loc_handle, attacker_locations) = scope.new_collection::<AttackerLocation, isize>();
            let (goal_handle, attacker_goals) = scope.new_collection::<AttackerGoal, isize>();

            // Build the attack graph
            let (exec_code, owns_machine, goals_reached) = build_attack_graph(
                &vulnerabilities,
                &network_access,
                &firewall_rules,
                &attacker_locations,
                &attacker_goals,
            );

            // Inspect changes to derived collections
            exec_code
                .inspect(move |x| {
                    if is_main {
                        let (data, time, diff) = x;
                        let sign = if *diff > 0 { "+" } else { "-" };
                        println!("  [t={}] {} {}", time, sign, data);
                    }
                })
                .probe_with(&mut probe);

            owns_machine
                .inspect(move |x| {
                    if is_main {
                        let (data, time, diff) = x;
                        let sign = if *diff > 0 { "+" } else { "-" };
                        println!("  [t={}] {} {}", time, sign, data);
                    }
                })
                .probe_with(&mut probe);

            goals_reached
                .inspect(move |x| {
                    if is_main {
                        let (data, time, diff) = x;
                        let sign = if *diff > 0 { "+" } else { "-" };
                        println!("  [t={}] {} {} (TARGET COMPROMISED!)", time, sign, data);
                    }
                })
                .probe_with(&mut probe);

            let probe_handle = goals_reached.probe();

            (
                vuln_handle,
                net_handle,
                fw_handle,
                loc_handle,
                goal_handle,
                probe_handle,
            )
        });

        // ====================================================================
        // PHASE 1: Initial Network State (Time 0)
        // ====================================================================
        if is_main {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("PHASE 1: Loading initial network state (time=0)");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("Network topology:");
            println!("  [Internet] → [DMZ/web01] → [Internal/db01] → [Target/admin01]");
            println!();
        }

        // Network topology
        let network_facts = vec![
            // Internet to DMZ
            NetworkAccess::new("internet", "web01", "http"),
            NetworkAccess::new("internet", "web01", "https"),
            // DMZ to Internal
            NetworkAccess::new("web01", "db01", "mysql"),
            NetworkAccess::new("web01", "db01", "ssh"),
            // Internal to Admin
            NetworkAccess::new("db01", "admin01", "ssh"),
            NetworkAccess::new("db01", "admin01", "smb"),
        ];

        // Vulnerabilities
        let vuln_facts = vec![
            // Web server has RCE vulnerability via HTTP
            Vulnerability::new("web01", "CVE-2024-1234", "http", Privilege::User),
            // Web server also vulnerable via HTTPS
            Vulnerability::new("web01", "CVE-2024-1234", "https", Privilege::User),
            // DB server has privilege escalation
            Vulnerability::new("db01", "CVE-2024-5678", "mysql", Privilege::Root),
            // DB server SSH vulnerability
            Vulnerability::new("db01", "CVE-2024-9999", "ssh", Privilege::User),
            // Admin server SMB vulnerability
            Vulnerability::new("admin01", "CVE-2024-8888", "smb", Privilege::Root),
        ];

        // Attacker starts on the internet
        let attacker_facts = vec![
            AttackerLocation::new("eve", "internet", Privilege::User),
        ];

        // Goal: compromise admin01
        let goal_facts = vec![
            AttackerGoal::new("eve", "admin01"),
        ];

        // Insert initial facts
        let start = Instant::now();

        for fact in network_facts {
            network_input.insert(fact);
        }
        for fact in vuln_facts {
            vuln_input.insert(fact);
        }
        for fact in attacker_facts {
            attacker_loc_input.insert(fact);
        }
        for fact in goal_facts {
            attacker_goal_input.insert(fact);
        }

        // Advance time to 1 and flush
        vuln_input.advance_to(1);
        network_input.advance_to(1);
        firewall_input.advance_to(1);
        attacker_loc_input.advance_to(1);
        attacker_goal_input.advance_to(1);
        vuln_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_loc_input.flush();
        attacker_goal_input.flush();

        // Wait for computation to complete
        while probe.less_than(&1) {
            worker.step();
        }

        if is_main {
            println!();
            println!("  ⏱  Initial computation completed in {:?}", start.elapsed());
            println!();
        }

        // ====================================================================
        // PHASE 2: Add a firewall rule (Time 1)
        // ====================================================================
        if is_main {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("PHASE 2: Adding firewall rule to block HTTP (time=1)");
            println!("         Rule: DENY internet → web01 on http");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
        }

        let start = Instant::now();

        // Add a firewall rule blocking HTTP
        firewall_input.insert(FirewallRule::deny("internet", "web01", "http"));

        // Advance time
        vuln_input.advance_to(2);
        network_input.advance_to(2);
        firewall_input.advance_to(2);
        attacker_loc_input.advance_to(2);
        attacker_goal_input.advance_to(2);
        vuln_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_loc_input.flush();
        attacker_goal_input.flush();

        while probe.less_than(&2) {
            worker.step();
        }

        if is_main {
            println!();
            println!("  ⏱  Incremental update completed in {:?}", start.elapsed());
            println!("  📝 Note: HTTP path removed, but HTTPS path still exists!");
            println!();
        }

        // ====================================================================
        // PHASE 3: Patch the critical vulnerability (Time 2)
        // ====================================================================
        if is_main {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("PHASE 3: Patching CVE-2024-1234 on web01 (time=2)");
            println!("         This removes the initial entry point!");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
        }

        let start = Instant::now();

        // Remove both vulnerabilities (HTTP and HTTPS) for CVE-2024-1234
        vuln_input.remove(Vulnerability::new("web01", "CVE-2024-1234", "http", Privilege::User));
        vuln_input.remove(Vulnerability::new("web01", "CVE-2024-1234", "https", Privilege::User));

        // Advance time
        vuln_input.advance_to(3);
        network_input.advance_to(3);
        firewall_input.advance_to(3);
        attacker_loc_input.advance_to(3);
        attacker_goal_input.advance_to(3);
        vuln_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_loc_input.flush();
        attacker_goal_input.flush();

        while probe.less_than(&3) {
            worker.step();
        }

        if is_main {
            println!();
            println!("  ⏱  Incremental update completed in {:?}", start.elapsed());
            println!("  🛡️  Target is now protected! All attack paths removed.");
            println!();
        }

        // ====================================================================
        // PHASE 4: New vulnerability discovered (Time 3)
        // ====================================================================
        if is_main {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("PHASE 4: New CVE discovered! CVE-2024-0DAY on web01 (time=3)");
            println!("         HTTPS service is vulnerable again.");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
        }

        let start = Instant::now();

        // Add a new vulnerability
        vuln_input.insert(Vulnerability::new("web01", "CVE-2024-0DAY", "https", Privilege::User));

        // Advance time
        vuln_input.advance_to(4);
        network_input.advance_to(4);
        firewall_input.advance_to(4);
        attacker_loc_input.advance_to(4);
        attacker_goal_input.advance_to(4);
        vuln_input.flush();
        network_input.flush();
        firewall_input.flush();
        attacker_loc_input.flush();
        attacker_goal_input.flush();

        while probe.less_than(&4) {
            worker.step();
        }

        if is_main {
            println!();
            println!("  ⏱  Incremental update completed in {:?}", start.elapsed());
            println!("  ⚠️  Attack paths restored via new vulnerability!");
            println!();
        }

        // ====================================================================
        // Summary
        // ====================================================================
        if is_main {
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("SUMMARY");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("This demonstration showed:");
            println!("  1. Initial attack graph computation from base facts");
            println!("  2. Incremental update when firewall rule added");
            println!("  3. Incremental update when vulnerability patched");
            println!("  4. Incremental update when new vulnerability discovered");
            println!();
            println!("Key observations:");
            println!("  • Updates only affected relevant derived facts");
            println!("  • No full recomputation was performed");
            println!("  • Changes propagated correctly through the graph");
            println!();
            println!("This is the power of differential dataflow for dynamic attack graphs!");
        }
    })
    .expect("Computation failed");
}
