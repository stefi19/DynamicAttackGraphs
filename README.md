# Dynamic Attack Graphs using Differential Dataflow

A Rust Proof of Concept demonstrating incremental maintenance of security attack graphs using [differential dataflow](https://github.com/TimelyDataflow/differential-dataflow).

## 🎯 Project Goal

Move beyond static attack graph analysis (like classical MulVAL) and implement a system that maintains the attack graph in **real-time** when facts change:
- Firewall rules updated
- Services patched
- New vulnerabilities discovered
- Network topology changes

## 📚 Research Documentation

This project includes comprehensive documentation:

- **[Phase 1: Conceptual Framework](docs/PHASE1_CONCEPTUAL_FRAMEWORK.md)**
  - Why Datalog over Prolog for attack graphs
  - DRed vs Backward/Forward algorithm comparison
  - Research gap analysis

- **[Phase 2: Architecture](docs/PHASE2_ARCHITECTURE.md)**
  - How differential dataflow handles updates
  - The `(data, time, diff)` tuple concept
  - Relation to DRed/B/F algorithms

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     BASE FACTS (Input)                      │
├─────────────────────────────────────────────────────────────┤
│  vulnerability    : (Host, CVE, Service, Privilege)         │
│  network_access   : (SrcHost, DstHost, Service)             │
│  firewall_rule    : (Src, Dst, Service, Action)             │
│  attacker_located : (Attacker, Host, Privilege)             │
│  attacker_goal    : (Attacker, TargetHost)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                    Differential Dataflow
                     (incremental rules)
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    DERIVED FACTS (Output)                   │
├─────────────────────────────────────────────────────────────┤
│  exec_code     : (Attacker, Host, Privilege)                │
│  owns_machine  : (Attacker, Host)                           │
│  goal_reached  : (Attacker, Target)                         │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))

### Build and Run

```bash
# Clone and enter the directory
cd /path/to/dynamic-attack-graphs

# Build the project
cargo build --release

# Run the main demonstration
cargo run --release

# Run the simple example
cargo run --release --example simple_demo
```

### Multi-threaded Execution

Differential dataflow scales across multiple cores:

```bash
# Run with 4 worker threads
cargo run --release -- -w4
```

## 📖 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║     Dynamic Attack Graphs using Differential Dataflow            ║
║                    Proof of Concept                              ║
╚══════════════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 1: Loading initial network state (time=0)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Network topology:
  [Internet] → [DMZ/web01] → [Internal/db01] → [Target/admin01]

  [t=0] + execCode(eve, internet, user)
  [t=0] + execCode(eve, web01, user)
  [t=0] + execCode(eve, db01, root)
  [t=0] + execCode(eve, admin01, root)
  [t=0] + ownsMachine(eve, db01)
  [t=0] + ownsMachine(eve, admin01)
  [t=0] + goalReached(eve, admin01) (TARGET COMPROMISED!)

  ⏱  Initial computation completed in 1.23ms

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PHASE 3: Patching CVE-2024-1234 on web01 (time=2)
         This removes the initial entry point!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [t=2] - execCode(eve, web01, user)
  [t=2] - execCode(eve, db01, root)
  [t=2] - execCode(eve, admin01, root)
  [t=2] - ownsMachine(eve, db01)
  [t=2] - ownsMachine(eve, admin01)
  [t=2] - goalReached(eve, admin01) (TARGET COMPROMISED!)

  ⏱  Incremental update completed in 0.15ms
  🛡️  Target is now protected! All attack paths removed.
```

## 🔧 MulVAL Rules Translation

This PoC translates MulVAL-style logical rules into differential dataflow operators:

### Original MulVAL Rule
```prolog
execCode(Attacker, Host, Priv) :-
    execCode(Attacker, SrcHost, _),
    hacl(SrcHost, Host, Service),
    vulExists(Host, _, Service, Priv).
```

### Differential Dataflow Translation
```rust
let exec_code = initial_exec.iterate(|inner_exec| {
    let access = access_by_src.enter(&inner_exec.scope());
    let vulns = vuln_by_host_service.enter(&inner_exec.scope());
    
    inner_exec
        .map(|ec| (ec.host.clone(), ec.attacker.clone()))
        .join(&access)
        .map(|(_src, (attacker, (dst, service)))| ((dst, service), attacker))
        .join(&vulns)
        .map(|((host, _), (attacker, privilege))| ExecCode {
            attacker, host, privilege
        })
        .concat(inner_exec)
        .distinct()
});
```

## 🧪 Key Concepts Demonstrated

### 1. Incremental Computation
Changes to input facts are processed **incrementally**, not by recomputing the entire graph:
- Adding a firewall rule → only affected paths are removed
- Patching a vulnerability → cascading removal of dependent attack paths
- New vulnerability → new attack paths added

### 2. The `(data, time, diff)` Tuple
All changes are represented as differences:
- `+1` = insertion
- `-1` = deletion
- Changes at the same time are batched for efficiency

### 3. Recursive Rule Evaluation
The `iterate` operator computes transitive closure until a fixpoint is reached, properly handling cycles in the attack graph.

## 📊 Performance Characteristics

| Operation | Complexity |
|-----------|------------|
| Insert/Delete base fact | O(log n) + O(affected derived) |
| Initial computation | O(facts × rules) |
| Incremental update | O(size of change) |

Expected performance (estimates based on differential dataflow benchmarks):

| Network Size | Initial | Incremental Update |
|--------------|---------|-------------------|
| 100 hosts | < 100ms | < 1ms |
| 1,000 hosts | < 1s | < 10ms |
| 10,000 hosts | < 30s | < 100ms |

## 🗂️ Project Structure

```
dynamic-attack-graphs/
├── Cargo.toml                 # Rust dependencies
├── README.md                  # This file
├── docs/
│   ├── PHASE1_CONCEPTUAL_FRAMEWORK.md
│   └── PHASE2_ARCHITECTURE.md
├── src/
│   ├── lib.rs                 # Library root
│   ├── main.rs                # Main demonstration
│   ├── schema.rs              # Data type definitions
│   └── rules.rs               # Attack graph rules
└── examples/
    └── simple_demo.rs         # Minimal example
```

## 🔬 Research Questions

This PoC enables investigation of:

1. **RQ1**: How does differential dataflow compare to classical DRed on attack graph workloads?
2. **RQ2**: What is the overhead of maintaining incrementality for large networks?
3. **RQ3**: Can we achieve sub-second updates for enterprise-scale networks (10K+ hosts)?
4. **RQ4**: How do different update patterns affect performance?

## 📚 References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
3. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993.
4. [Differential Dataflow Documentation](https://timelydataflow.github.io/differential-dataflow/)

## 📄 License

MIT License
