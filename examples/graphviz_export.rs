// Graphviz Export Demo - Generates visual attack graphs
// Run with: cargo run --release --example graphviz_export
// Then: dot -Tpng graph_initial.dot -o graph_initial.png
//       dot -Tpng graph_final.dot -o graph_final.png

use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};

use differential_dataflow::input::Input;
use differential_dataflow::operators::iterate::Iterate;
use differential_dataflow::operators::join::Join;
use differential_dataflow::operators::reduce::Threshold;
use timely::dataflow::operators::probe::Handle;
use timely::dataflow::operators::Probe;

/// Represents the attack graph state for visualization
#[derive(Clone, Default)]
struct AttackGraphState {
    nodes: HashSet<String>,
    edges: HashSet<(String, String, String)>, // (src, dst, service)
    compromised: HashSet<String>,             // nodes attacker can reach
    attacker_start: String,
    target_node: String,
}

impl AttackGraphState {
    fn export_to_dot(&self, filename: &str, title: &str) -> std::io::Result<()> {
        let mut file = File::create(filename)?;
        
        writeln!(file, "digraph AttackGraph {{")?;
        writeln!(file, "    label=\"{}\";", title)?;
        writeln!(file, "    labelloc=\"t\";")?;
        writeln!(file, "    fontsize=20;")?;
        writeln!(file, "    rankdir=LR;")?;
        writeln!(file, "    node [shape=box, style=filled];")?;
        writeln!(file)?;
        
        // Define node styles
        for node in &self.nodes {
            let (color, label_suffix) = if node == &self.attacker_start {
                ("lightblue", " [ATTACKER]")
            } else if node == &self.target_node {
                if self.compromised.contains(node) {
                    ("red", " [TARGET - COMPROMISED!]")
                } else {
                    ("lightgreen", " [TARGET - SAFE]")
                }
            } else if self.compromised.contains(node) {
                ("orange", " [COMPROMISED]")
            } else {
                ("white", "")
            };
            
            writeln!(file, "    \"{}\" [fillcolor={}, label=\"{}{}\"];", 
                     node, color, node, label_suffix)?;
        }
        writeln!(file)?;
        
        // Define edges with attack path highlighting
        for (src, dst, service) in &self.edges {
            let is_attack_path = self.compromised.contains(src) && self.compromised.contains(dst);
            let (color, penwidth) = if is_attack_path {
                ("red", "2.0")
            } else {
                ("black", "1.0")
            };
            
            writeln!(file, "    \"{}\" -> \"{}\" [label=\"{}\", color={}, penwidth={}];",
                     src, dst, service, color, penwidth)?;
        }
        
        writeln!(file, "}}")?;
        
        println!("Exported: {}", filename);
        Ok(())
    }
}

fn main() {
    println!("=================================================");
    println!("  Attack Graph Visualization with Graphviz");
    println!("=================================================\n");

    // Shared state for collecting attack graph data
    let graph_state = Arc::new(Mutex::new(AttackGraphState::default()));
    let graph_state_clone = Arc::clone(&graph_state);

    timely::execute_directly(move |worker| {
        let mut probe = Handle::new();

        let compromised_nodes = Arc::new(Mutex::new(HashSet::<String>::new()));
        let compromised_clone = Arc::clone(&compromised_nodes);

        let (mut vuln_input, mut network_input, mut attacker_input) = 
            worker.dataflow::<usize, _, _>(|scope| {
            
            // Vulnerability: (host, service, is_root)
            let (vuln_handle, vulns) = scope.new_collection::<(String, String, bool), isize>();
            
            // Network: (src, dst, service)
            let (net_handle, network) = scope.new_collection::<(String, String, String), isize>();
            
            // Attacker: (attacker_id, host)
            let (att_handle, attacker) = scope.new_collection::<(String, String), isize>();

            // Compute reachability
            let reachable = attacker.iterate(|inner| {
                let net_in_scope = network.enter(&inner.scope());
                let vulns_in_scope = vulns.enter(&inner.scope())
                    .map(|(h, s, _)| (h, s))
                    .distinct();

                inner
                    .map(|(att, host)| (host, att))
                    .join(&net_in_scope.map(|(s, d, svc)| (s, (d, svc))))
                    .map(|(_, (att, (dst, svc)))| ((dst.clone(), svc), (att, dst)))
                    .semijoin(&vulns_in_scope)
                    .map(|((_, _), (att, dst))| (att, dst))
                    .concat(inner)
                    .distinct()
            });

            // Track compromised nodes
            let compromised_for_inspect = compromised_clone;
            reachable
                .inspect(move |((_, host), _, diff)| {
                    let mut set = compromised_for_inspect.lock().unwrap();
                    if *diff > 0 {
                        set.insert(host.clone());
                    } else {
                        set.remove(host);
                    }
                })
                .probe_with(&mut probe);

            (vuln_handle, net_handle, att_handle)
        });

        // =====================================================
        // Build a 10-node chain network for visualization
        // =====================================================
        // Network: attacker -> node_0 -> node_1 -> ... -> node_8 -> target
        
        let num_nodes = 10;
        let mut nodes = HashSet::new();
        let mut edges = HashSet::new();
        
        // Attacker starting point
        nodes.insert("attacker".to_string());
        attacker_input.insert(("eve".into(), "attacker".into()));
        vuln_input.insert(("attacker".into(), "ssh".into(), true));
        
        // Chain of nodes
        let mut prev = "attacker".to_string();
        for i in 0..num_nodes - 1 {
            let current = format!("node_{}", i);
            nodes.insert(current.clone());
            
            network_input.insert((prev.clone(), current.clone(), "ssh".into()));
            edges.insert((prev.clone(), current.clone(), "ssh".to_string()));
            
            vuln_input.insert((current.clone(), "ssh".into(), true));
            prev = current;
        }
        
        // Target node
        let target = "target".to_string();
        nodes.insert(target.clone());
        network_input.insert((prev.clone(), target.clone(), "ssh".into()));
        edges.insert((prev.clone(), target.clone(), "ssh".to_string()));
        vuln_input.insert((target.clone(), "ssh".into(), true));
        
        // Setup initial graph state
        {
            let mut state = graph_state_clone.lock().unwrap();
            state.nodes = nodes;
            state.edges = edges;
            state.attacker_start = "attacker".to_string();
            state.target_node = "target".to_string();
        }

        // Advance to timestamp 1
        vuln_input.advance_to(1);
        network_input.advance_to(1);
        attacker_input.advance_to(1);
        vuln_input.flush();
        network_input.flush();
        attacker_input.flush();

        while probe.less_than(&1) {
            worker.step();
        }

        // Export initial graph
        {
            let mut state = graph_state_clone.lock().unwrap();
            state.compromised = compromised_nodes.lock().unwrap().clone();
            state.export_to_dot("graph_initial.dot", 
                "Initial Attack Graph - All nodes compromised").unwrap();
        }
        
        println!("\nInitial state: Attacker can reach all {} nodes including TARGET\n", num_nodes);

        // =====================================================
        // PATCH: Remove vulnerability at node_4 (middle of chain)
        // =====================================================
        println!("Applying patch: Removing vulnerability at node_4...\n");
        
        vuln_input.remove(("node_4".into(), "ssh".into(), true));
        
        vuln_input.advance_to(2);
        network_input.advance_to(2);
        attacker_input.advance_to(2);
        vuln_input.flush();
        network_input.flush();
        attacker_input.flush();

        while probe.less_than(&2) {
            worker.step();
        }

        // Export final graph
        {
            let mut state = graph_state_clone.lock().unwrap();
            state.compromised = compromised_nodes.lock().unwrap().clone();
            state.export_to_dot("graph_final.dot", 
                "After Patching node_4 - Attack path broken").unwrap();
        }
        
        let final_compromised = compromised_nodes.lock().unwrap().len();
        println!("After patch: Attacker can only reach {} nodes (node_4 to target are safe)\n", 
                 final_compromised);
    });

    println!("=================================================");
    println!("  Visualization files generated!");
    println!("=================================================");
    println!();
    println!("To convert to PNG images, run:");
    println!("  dot -Tpng graph_initial.dot -o graph_initial.png");
    println!("  dot -Tpng graph_final.dot -o graph_final.png");
    println!();
    println!("Or use the provided script:");
    println!("  ./generate_graphs.sh");
    println!();
    println!("Legend:");
    println!("  - Blue node: Attacker starting position");
    println!("  - Orange nodes: Compromised by attacker");
    println!("  - Red node: Target compromised");
    println!("  - Green node: Target safe");
    println!("  - Red edges: Active attack path");
    println!("  - Black edges: Network connection (not exploited)");
}
