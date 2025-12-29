# Dynamic Attack Graphs using Differential Dataflow

A Rust implementation demonstrating incremental maintenance of security attack graphs using differential dataflow.

## Project Goal

This project moves beyond static attack graph analysis (like MulVAL) to implement a system that maintains the attack graph in real-time when facts change:
- Firewall rules updated
- Services patched
- New vulnerabilities discovered
- Network topology changes

## Documentation

- [Phase 1: Conceptual Framework](docs/PHASE1_CONCEPTUAL_FRAMEWORK.md) - Why Datalog and comparison of incremental algorithms
- [Phase 2: Architecture](docs/PHASE2_ARCHITECTURE.md) - How differential dataflow handles updates

## Architecture

```
+-----------------------------------------------------------+
|                     BASE FACTS (Input)                    |
+-----------------------------------------------------------+
|  vulnerability    : (Host, CVE, Service, Privilege)       |
|  network_access   : (SrcHost, DstHost, Service)           |
|  firewall_rule    : (Src, Dst, Service, Action)           |
|  attacker_located : (Attacker, Host, Privilege)           |
|  attacker_goal    : (Attacker, TargetHost)                |
+-----------------------------------------------------------+
                              |
                    Differential Dataflow
                     (incremental rules)
                              |
                              v
+-----------------------------------------------------------+
|                    DERIVED FACTS (Output)                 |
+-----------------------------------------------------------+
|  exec_code     : (Attacker, Host, Privilege)              |
|  owns_machine  : (Attacker, Host)                         |
|  goal_reached  : (Attacker, Target)                       |
+-----------------------------------------------------------+
```

## Quick Start

### Requirements

- Rust 1.70+ (install from rustup.rs)

### Build and Run

```bash
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

## Example Output

```
========================================================================
     Dynamic Attack Graphs using Differential Dataflow
                    Proof of Concept
========================================================================

------------------------------------------------------------------------
PHASE 1: Loading initial network state (time=0)
------------------------------------------------------------------------

Network topology:
  [Internet] -> [DMZ/web01] -> [Internal/db01] -> [Target/admin01]

  [t=0] + execCode(eve, internet, user)
  [t=0] + execCode(eve, web01, user)
  [t=0] + execCode(eve, db01, root)
  [t=0] + execCode(eve, admin01, root)
  [t=0] + ownsMachine(eve, db01)
  [t=0] + ownsMachine(eve, admin01)
  [t=0] + goalReached(eve, admin01) (TARGET COMPROMISED)

  Initial computation completed in 1.23ms

------------------------------------------------------------------------
PHASE 3: Patching CVE-2024-1234 on web01 (time=2)
------------------------------------------------------------------------

  [t=2] - execCode(eve, web01, user)
  [t=2] - execCode(eve, db01, root)
  [t=2] - execCode(eve, admin01, root)
  [t=2] - ownsMachine(eve, db01)
  [t=2] - ownsMachine(eve, admin01)
  [t=2] - goalReached(eve, admin01) (TARGET COMPROMISED)

  Incremental update completed in 0.15ms
  Target is now protected - all attack paths removed
```

## MulVAL Rules Translation

This project translates MulVAL-style logical rules into differential dataflow operators.

### Original MulVAL Rule
```prolog
execCode(Attacker, Host, Priv) :-
    execCode(Attacker, SrcHost, _),
    hacl(SrcHost, Host, Service),
    vulExists(Host, _, Service, Priv).
```

### Differential Dataflow Translation
```rust
let all_code_executions = initial_code_execution.iterate(|current_executions| {
    let access_in_scope = network_access_by_source.enter(&current_executions.scope());
    let vulns_in_scope = vulnerabilities_by_host_and_service.enter(&current_executions.scope());
    
    current_executions
        .map(|execution| (execution.compromised_host.clone(), execution.attacker_id.clone()))
        .join(&access_in_scope)
        .map(|(_source, (attacker_id, (destination, service)))| ((destination, service), attacker_id))
        .join(&vulns_in_scope)
        .map(|((host, _), (attacker_id, privilege))| AttackerCodeExecution {
            attacker_id, compromised_host: host, obtained_privilege: privilege
        })
        .concat(current_executions)
        .distinct()
});
```

## Project Structure

```
src/
  schema.rs   - Data type definitions
  rules.rs    - Attack graph rule implementation
  main.rs     - Main demonstration program
  lib.rs      - Library exports

examples/
  simple_demo.rs - Minimal working example

docs/
  PHASE1_CONCEPTUAL_FRAMEWORK.md - Theory and background
  PHASE2_ARCHITECTURE.md         - Implementation details
```

## References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
3. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993.
