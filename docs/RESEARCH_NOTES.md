# Research Notes: Dynamic Attack Graphs

## Executive Summary

This project explores the intersection of **logic-based security analysis** and **incremental computation**. We implement a Proof of Concept demonstrating how differential dataflow can maintain attack graphs in real-time as network configurations change.

---

## Key Findings

### 1. Why Datalog Works for Attack Graphs

| Requirement | Prolog | Datalog | Why It Matters |
|-------------|--------|---------|----------------|
| Termination guaranteed | ✗ | ✓ | Security analysis must complete |
| Complete answer set | ✗ | ✓ | All attack paths must be found |
| Bottom-up evaluation | ✗ | ✓ | Enables incrementality |
| Handles cycles | Problematic | Natural | Networks have loops |
| Parallelizable | Hard | Easy | Scale to large networks |

### 2. Differential Dataflow vs Traditional Approaches

**Traditional (MulVAL/XSB Prolog):**
```
Change fact → Retract → Re-run full analysis → 10s-minutes
```

**Differential Dataflow:**
```
Change fact → Propagate diff → Updated graph → milliseconds
```

### 3. The Research Gap We Address

| System | Incrementality | Open Source | Security Focus |
|--------|---------------|-------------|----------------|
| MulVAL | ✗ None | ✓ | ✓ |
| Soufflé | ✗ DRed (partial) | ✓ | ✗ |
| LogicBlox | ✓ Full | ✗ | ✗ |
| **This PoC** | ✓ Full | ✓ | ✓ |

---

## Technical Architecture

### Data Flow

```
                    ┌──────────────┐
                    │  Fact Store  │
                    │  (vulns,     │
                    │   network,   │
                    │   firewall)  │
                    └──────┬───────┘
                           │ changes as (data, time, diff)
                           ▼
┌──────────────────────────────────────────────────────────┐
│                  DIFFERENTIAL DATAFLOW                   │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐            │
│  │   Map    │──▶│   Join   │──▶│  Iterate │            │
│  └──────────┘   └──────────┘   └──────────┘            │
│        ▲                              │                 │
│        │         Arrangements         │                 │
│        └────────(shared indexes)──────┘                 │
└──────────────────────────────────────────────────────────┘
                           │
                           ▼ diffs only!
                    ┌──────────────┐
                    │   Outputs    │
                    │  (execCode,  │
                    │   ownsMachine│
                    │   goalReached│
                    └──────────────┘
```

### Rule Translation Pattern

**Datalog Rule:**
```prolog
H(X,Y) :- A(X,Z), B(Z,Y).
```

**Differential Dataflow:**
```rust
let h = a
    .map(|(x, z)| (z, x))      // Key by join variable
    .join(&b.map(|(z, y)| (z, y)))
    .map(|(z, (x, y))| (x, y)); // Project result
```

---

## Implementation Details

### Schema Design

We chose a **normalized relational schema** mirroring MulVAL's predicates:

```rust
// Base facts (EDB)
struct Vulnerability { host, cve_id, service, grants_privilege }
struct NetworkAccess { src_host, dst_host, service }
struct FirewallRule { src, dst, service, action }
struct AttackerLocation { attacker, host, privilege }
struct AttackerGoal { attacker, target_host }

// Derived facts (IDB)
struct ExecCode { attacker, host, privilege }
struct OwnsMachine { attacker, host }
struct GoalReached { attacker, target }
```

### Iteration for Transitive Closure

The key challenge is computing **transitive attack propagation**. We use differential dataflow's `iterate` operator:

```rust
exec_code.iterate(|inner| {
    // 1. From current positions, find reachable hosts
    // 2. Check if reachable hosts are vulnerable
    // 3. Add new execution capabilities
    // 4. Deduplicate and continue until fixpoint
})
```

---

## Experimental Scenarios

### Scenario 1: Firewall Rule Added
- **Input:** Add deny rule (internet → web01 : http)
- **Expected:** HTTP attack path removed, HTTPS path remains
- **Demonstrates:** Partial invalidation without full recomputation

### Scenario 2: Vulnerability Patched
- **Input:** Remove CVE-2024-1234 from web01
- **Expected:** All dependent attack paths removed (cascade)
- **Demonstrates:** Proper handling of cascading deletions

### Scenario 3: New Vulnerability Discovered
- **Input:** Add CVE-2024-0DAY to web01
- **Expected:** Attack paths restored
- **Demonstrates:** Incremental addition propagation

---

## Performance Expectations

Based on differential dataflow's design principles:

| Metric | Expected | Rationale |
|--------|----------|-----------|
| Initial computation | O(V × E × R) | Must process all facts once |
| Single update | O(Δ × log n) | Only changed portions |
| Memory | O(facts + history) | Arrangements use memory |
| Latency | Sub-millisecond | For small changes |
| Throughput | 100K+ updates/sec | With batching |

---

## Future Research Directions

### Short-term
1. Add more MulVAL rules (privilege escalation, multi-stage attacks)
2. Benchmark against Soufflé's DRed implementation
3. Add support for negation (stratified)

### Medium-term
1. Connect to real vulnerability databases (NVD, CVE)
2. Ingest network topology from scanning tools
3. Build a real-time dashboard for security monitoring

### Long-term
1. Distributed execution across clusters
2. Integration with SIEM systems
3. Formal verification of attack graph completeness

---

## Running the Code

```bash
# Build release version
cargo build --release

# Run main demonstration
cargo run --release

# Run simple example
cargo run --release --example simple_demo

# Run with multiple workers
cargo run --release -- -w4
```

---

## References

1. **MulVAL** - Ou, X., et al. "A Scalable Approach to Attack Graph Generation." CCS 2006.
2. **Differential Dataflow** - McSherry, F., et al. "Differential Dataflow." CIDR 2013.
3. **DRed Algorithm** - Gupta, A., Mumick, I. "Maintenance of Materialized Views." VLDB Journal 1995.
4. **B/F Algorithm** - Motik, B., et al. "Incremental Update of Datalog Materialization." AAAI 2015.

---

## Contact

For questions about this research project, please contact the authors.
