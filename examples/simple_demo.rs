//! Simple demonstration of differential dataflow for attack graphs
//!
//! This is a minimal example showing the core concepts.

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
        let mut probe = Handle::new();

        // Create the dataflow
        let (mut vulns, mut access, mut attacker) = worker.dataflow::<usize, _, _>(|scope| {
            // Input collections
            // Vulnerability: (host, service, grants_root)
            let (vuln_input, vulns) = scope.new_collection::<(String, String, bool), isize>();
            
            // Network access: (src, dst, service)
            let (access_input, access) = scope.new_collection::<(String, String, String), isize>();
            
            // Attacker location: (attacker_id, host)
            let (attacker_input, attacker) = scope.new_collection::<(String, String), isize>();

            // RULE: Compute execCode transitively
            // 
            // MulVAL equivalent:
            //   execCode(Attacker, Host) :- attackerLocated(Attacker, Host).
            //   execCode(Attacker, DstHost) :-
            //       execCode(Attacker, SrcHost),
            //       hacl(SrcHost, DstHost, Service),
            //       vulExists(DstHost, Service).

            // Initial attacker positions
            let initial = attacker.clone();

            // Recursive expansion
            let exec_code = initial.iterate(|inner| {
                let access = access.enter(&inner.scope());
                // For semijoin, we need just the keys (not key-value pairs)
                let vuln_keys = vulns.enter(&inner.scope())
                    .map(|(host, service, _root)| (host, service))
                    .distinct();

                // Key execCode by host to join with access
                inner
                    .map(|(attacker, host)| (host, attacker))
                    // Join with network access (keyed by src host)
                    .join(&access.map(|(src, dst, svc)| (src, (dst, svc))))
                    // Result: (src_host, (attacker, (dst_host, service)))
                    .map(|(_src, (attacker, (dst, svc)))| ((dst.clone(), svc), (attacker, dst)))
                    // Join with vulnerabilities (keyed by (host, service))
                    .semijoin(&vuln_keys)
                    // Extract (attacker, dst_host)
                    .map(|((_host, _svc), (attacker, dst))| (attacker, dst))
                    // Combine with existing and deduplicate
                    .concat(inner)
                    .distinct()
            });

            // Compute which hosts attacker "owns" (root access)
            let owns = exec_code
                .map(|(attacker, host)| (host.clone(), attacker))
                .join(&vulns.filter(|(_h, _s, root)| *root).map(|(h, _s, _r)| (h, ())))
                .map(|(host, (attacker, ()))| (attacker, host));

            // Print changes
            exec_code
                .inspect(|x| {
                    let ((attacker, host), time, diff) = x;
                    let sign = if *diff > 0 { "+" } else { "-" };
                    println!("  [t={}] {} execCode({}, {})", time, sign, attacker, host);
                })
                .probe_with(&mut probe);

            owns
                .inspect(|x| {
                    let ((attacker, host), time, diff) = x;
                    let sign = if *diff > 0 { "+" } else { "-" };
                    println!("  [t={}] {} owns({}, {}) 🎯", time, sign, attacker, host);
                })
                .probe_with(&mut probe);

            (vuln_input, access_input, attacker_input)
        });

        // ================================================================
        // Time 0: Initial state
        // ================================================================
        println!("Time 0: Initial network");
        println!("------------------------");
        
        // Simple network: internet -> web -> db
        access.insert(("internet".into(), "web".into(), "http".into()));
        access.insert(("web".into(), "db".into(), "mysql".into()));
        
        // Vulnerabilities
        vulns.insert(("web".into(), "http".into(), false));  // user-level
        vulns.insert(("db".into(), "mysql".into(), true));   // root!
        
        // Attacker starts on internet
        attacker.insert(("eve".into(), "internet".into()));

        vulns.advance_to(1); vulns.flush();
        access.advance_to(1); access.flush();
        attacker.advance_to(1); attacker.flush();

        while probe.less_than(&1) { worker.step(); }
        println!();

        // ================================================================
        // Time 1: Patch the web vulnerability
        // ================================================================
        println!("Time 1: Patching web server vulnerability");
        println!("------------------------------------------");
        
        let start = Instant::now();
        vulns.remove(("web".into(), "http".into(), false));

        vulns.advance_to(2); vulns.flush();
        access.advance_to(2); access.flush();
        attacker.advance_to(2); attacker.flush();

        while probe.less_than(&2) { worker.step(); }
        println!("  Computed in {:?}", start.elapsed());
        println!();

        // ================================================================
        // Time 2: New vulnerability discovered
        // ================================================================
        println!("Time 2: New vulnerability on web server!");
        println!("-----------------------------------------");
        
        let start = Instant::now();
        vulns.insert(("web".into(), "http".into(), false));

        vulns.advance_to(3); vulns.flush();
        access.advance_to(3); access.flush();
        attacker.advance_to(3); attacker.flush();

        while probe.less_than(&3) { worker.step(); }
        println!("  Computed in {:?}", start.elapsed());
        println!();

        println!("Demo complete!");
    }).expect("Computation failed");
}
