// Simple demonstration of differential dataflow for attack graphs
// A minimal example showing how the incremental updates work

use std::time::Instant;

use differential_dataflow::input::Input;
use differential_dataflow::operators::iterate::Iterate;
use differential_dataflow::operators::join::Join;
use differential_dataflow::operators::reduce::Threshold;
use timely::dataflow::operators::probe::Handle;
use timely::dataflow::operators::Probe;

fn main() {
    println!("Simple Attack Graph Demo");
    println!("========================\n");

    timely::execute_from_args(std::env::args(), |worker| {
        let mut computation_probe = Handle::new();

        // Create the dataflow
        let (mut vulnerability_input, mut network_access_input, mut attacker_input) = worker.dataflow::<usize, _, _>(|scope| {
            // Input collections with simple tuple types
            // Vulnerability: (host_name, service_name, grants_root_access)
            let (vuln_handle, vulnerability_collection) = scope.new_collection::<(String, String, bool), isize>();
            
            // Network access: (source_host, destination_host, service_name)
            let (access_handle, network_access_collection) = scope.new_collection::<(String, String, String), isize>();
            
            // Attacker location: (attacker_id, current_host)
            let (attacker_handle, attacker_location_collection) = scope.new_collection::<(String, String), isize>();

            // Compute execCode transitively using iteration
            // The rule says: attacker can execute code on any host they can reach
            // through the network if that host has a vulnerability

            // Start with initial attacker positions
            let initial_attacker_positions = attacker_location_collection.clone();

            // Keep expanding until no new hosts are found
            let all_code_executions = initial_attacker_positions.iterate(|current_positions| {
                let network_access_in_scope = network_access_collection.enter(&current_positions.scope());
                
                // Get just the host+service pairs that have vulnerabilities
                let vulnerable_host_service_pairs = vulnerability_collection.enter(&current_positions.scope())
                    .map(|(host_name, service_name, _grants_root)| (host_name, service_name))
                    .distinct();

                // From current positions, find reachable hosts via network
                current_positions
                    .map(|(attacker_id, current_host)| (current_host, attacker_id))
                    // Join with network access to find where attacker can go
                    .join(&network_access_in_scope.map(|(source, destination, service)| (source, (destination, service))))
                    // Result: (source_host, (attacker_id, (destination_host, service)))
                    .map(|(_source, (attacker_id, (destination, service)))| ((destination.clone(), service), (attacker_id, destination)))
                    // Keep only destinations that have vulnerabilities
                    .semijoin(&vulnerable_host_service_pairs)
                    // Extract attacker and destination host
                    .map(|((_host, _service), (attacker_id, destination))| (attacker_id, destination))
                    // Combine with existing positions and remove duplicates
                    .concat(current_positions)
                    .distinct()
            });

            // Attacker owns machine if the vulnerability grants root
            let machines_with_root_access = all_code_executions
                .map(|(attacker_id, host_name)| (host_name.clone(), attacker_id))
                .join(&vulnerability_collection.filter(|(_host, _service, grants_root)| *grants_root).map(|(host, _service, _root)| (host, ())))
                .map(|(host_name, (attacker_id, ()))| (attacker_id, host_name));

            // Print changes to code execution
            all_code_executions
                .inspect(|change| {
                    let ((attacker_id, host_name), timestamp, difference) = change;
                    let change_type = if *difference > 0 { "+" } else { "-" };
                    println!("  [t={}] {} execCode({}, {})", timestamp, change_type, attacker_id, host_name);
                })
                .probe_with(&mut computation_probe);

            // Print changes to machine ownership
            machines_with_root_access
                .inspect(|change| {
                    let ((attacker_id, host_name), timestamp, difference) = change;
                    let change_type = if *difference > 0 { "+" } else { "-" };
                    println!("  [t={}] {} owns({}, {}) TARGET", timestamp, change_type, attacker_id, host_name);
                })
                .probe_with(&mut computation_probe);

            (vuln_handle, access_handle, attacker_handle)
        });

        // ----------------------------------------------------------------
        // Timestamp 0: Initial network state
        // ----------------------------------------------------------------
        println!("Timestamp 0: Initial network");
        println!("----------------------------");
        
        // Simple network: internet -> web -> db
        network_access_input.insert(("internet".into(), "web".into(), "http".into()));
        network_access_input.insert(("web".into(), "db".into(), "mysql".into()));
        
        // Vulnerabilities (host, service, grants_root)
        vulnerability_input.insert(("web".into(), "http".into(), false));  // user level only
        vulnerability_input.insert(("db".into(), "mysql".into(), true));   // grants root
        
        // Attacker starts on the internet
        attacker_input.insert(("eve".into(), "internet".into()));

        vulnerability_input.advance_to(1); vulnerability_input.flush();
        network_access_input.advance_to(1); network_access_input.flush();
        attacker_input.advance_to(1); attacker_input.flush();

        while computation_probe.less_than(&1) { worker.step(); }
        println!();

        // ----------------------------------------------------------------
        // Timestamp 1: Patch the web server vulnerability
        // ----------------------------------------------------------------
        println!("Timestamp 1: Patching web server vulnerability");
        println!("-----------------------------------------------");
        
        let update_start = Instant::now();
        vulnerability_input.remove(("web".into(), "http".into(), false));

        vulnerability_input.advance_to(2); vulnerability_input.flush();
        network_access_input.advance_to(2); network_access_input.flush();
        attacker_input.advance_to(2); attacker_input.flush();

        while computation_probe.less_than(&2) { worker.step(); }
        println!("  Computed in {:?}", update_start.elapsed());
        println!();

        // ----------------------------------------------------------------
        // Timestamp 2: New vulnerability discovered on web server
        // ----------------------------------------------------------------
        println!("Timestamp 2: New vulnerability on web server");
        println!("---------------------------------------------");
        
        let update_start = Instant::now();
        vulnerability_input.insert(("web".into(), "http".into(), false));

        vulnerability_input.advance_to(3); vulnerability_input.flush();
        network_access_input.advance_to(3); network_access_input.flush();
        attacker_input.advance_to(3); attacker_input.flush();

        while computation_probe.less_than(&3) { worker.step(); }
        println!("  Computed in {:?}", update_start.elapsed());
        println!();

        println!("Demo complete.");
    })
    .expect("Computation failed");
}
