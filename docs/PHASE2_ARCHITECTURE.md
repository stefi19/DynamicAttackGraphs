# Phase 2: Architecture & Tooling

## Differential Dataflow for Dynamic Attack Graphs

This document explains how differential dataflow handles incremental updates and how this relates to the DRed/B/F algorithms described in Phase 1.

---

## 1. Differential Dataflow Core Concepts

### 1.1 The (data, time, diff) Tuple

Differential dataflow represents all data as a **stream of changes**. Each change is a tuple:

```rust
(data: D, time: T, diff: R)
```

Where:
- **`data: D`** - The actual record (e.g., a vulnerability, an attack path)
- **`time: T`** - A logical timestamp (version/epoch of the database)
- **`diff: R`** - A difference value (typically +1 for insertion, -1 for deletion)

**Example:**

```rust
// At time 0: Insert a vulnerability
(Vulnerability { host: "web01", cve: "CVE-2024-1234" }, time: 0, diff: +1)

// At time 5: Patch the vulnerability (remove it)
(Vulnerability { host: "web01", cve: "CVE-2024-1234" }, time: 5, diff: -1)
```

### 1.2 Collections as Multisets

A **collection** at any time `t` is the multiset obtained by summing all diffs up to time `t`:

```
Collection[t] = Σ { (data, diff) | time ≤ t }
```

If the sum of diffs for a record is:
- **> 0**: Record is present (with that multiplicity)
- **= 0**: Record is absent
- **< 0**: Invalid (but differential dataflow handles this correctly)

### 1.3 Operators Preserve Differences

All operators (`map`, `filter`, `join`, `reduce`) are defined on **differences**, not full collections:

```rust
// Conceptually:
output_diff[t] = operator(input_diff[t])

// For joins:
ΔC = (ΔA ⋈ B) ∪ (A ⋈ ΔB) ∪ (ΔA ⋈ ΔB)
```

This is the key insight: **we only process changes, not the full data**.

---

## 2. How This Relates to DRed and B/F

### 2.1 Differential Dataflow vs DRed

| Aspect | DRed | Differential Dataflow |
|--------|------|----------------------|
| **Deletion handling** | Over-delete, then rederive | Changes cancel out mathematically |
| **Rederivation** | Explicit second pass | Implicit through diff arithmetic |
| **Multiple derivations** | Must track and re-check | Natural: diffs accumulate |

**Key Difference**: DRed has a "two-phase" approach (delete, rederive). Differential dataflow processes insertions and deletions **uniformly** - they're just different signs on the diff.

### 2.2 Differential Dataflow vs B/F

| Aspect | B/F Algorithm | Differential Dataflow |
|--------|--------------|----------------------|
| **Counting derivations** | Explicit count per fact | Implicit in diff accumulation |
| **When fact disappears** | Count reaches 0 | Sum of diffs reaches 0 |
| **Provenance** | Stored separately | Encoded in the diff stream |

**Key Similarity**: Both approaches use **counting** to determine when a derived fact should be removed. The B/F algorithm counts derivations explicitly; differential dataflow achieves the same effect through the algebra of differences.

### 2.3 What Differential Dataflow Does "Natively"

Differential dataflow implements something **more general** than either DRed or B/F:

1. **Arbitrary lattice times**: Not just a linear sequence of updates, but any partial order
2. **Batch updates**: Multiple changes at the same logical time
3. **Parallel processing**: Scales across cores and machines
4. **Streaming**: Continuous processing of updates

```rust
// Example: Multiple changes at time 5
input.advance_to(5);
input.insert(("web01", "CVE-2024-5678"));  // diff = +1
input.remove(("web01", "CVE-2024-1234"));  // diff = -1
input.flush();
// Both changes processed together, efficiently
```

---

## 3. Architecture for Attack Graphs

### 3.1 Data Model

We model the attack graph domain with these collections:

```
┌─────────────────────────────────────────────────────────────┐
│                     BASE FACTS (EDB)                        │
├─────────────────────────────────────────────────────────────┤
│  vulnerability    : Collection<(Host, CVE, Service, Priv)>  │
│  network_access   : Collection<(SrcHost, DstHost, Service)> │
│  attacker_located : Collection<(Attacker, Host)>            │
│  attacker_goal    : Collection<(Attacker, Host)>            │
│  firewall_rule    : Collection<(Src, Dst, Service, Action)> │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    DERIVED FACTS (IDB)                      │
├─────────────────────────────────────────────────────────────┤
│  effective_access : Collection<(Src, Dst, Service)>         │
│  exec_code        : Collection<(Attacker, Host, Priv)>      │
│  owns_machine     : Collection<(Attacker, Host)>            │
│  goal_reached     : Collection<(Attacker, Goal)>            │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Dataflow Pipeline

```
                    ┌──────────────────┐
                    │   Input Handles  │
                    │  (vulnerability, │
                    │  network_access, │
                    │  firewall_rule)  │
                    └────────┬─────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────────┐
│                     DATAFLOW COMPUTATION                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Rule 1: Compute effective network access                │  │
│  │  effective_access = network_access.antijoin(blocked)     │  │
│  └──────────────────────────────────────────────────────────┘  │
│                             │                                  │
│                             ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Rule 2: Attacker gains code execution                   │  │
│  │  exec_code = (attacker_located                           │  │
│  │              .join(effective_access)                     │  │
│  │              .join(vulnerability))                       │  │
│  │              .map(derive_execution)                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                             │                                  │
│                             ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Rule 3: Transitive access (ITERATE)                     │  │
│  │  exec_code.iterate(|inner| {                             │  │
│  │      inner.join(effective_access)                        │  │
│  │           .join(vulnerability)                           │  │
│  │           .concat(inner).distinct()                      │  │
│  │  })                                                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                             │                                  │
│                             ▼                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  Rule 4: Privilege escalation                            │  │
│  │  owns_machine = exec_code.filter(|e| e.priv == Root)     │  │
│  └──────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │   Output Probe   │
                    │  (goal_reached,  │
                    │   attack_paths)  │
                    └──────────────────┘
```

### 3.3 Handling Updates

When a fact changes, only the affected part of the graph is recomputed:

```
Time 0: Initial network state
        → Full computation, establish baseline

Time 1: Firewall rule added (block port 443 to web01)
        → Δ effective_access computed
        → Δ exec_code propagated
        → Δ owns_machine updated
        → Changes reported to output

Time 2: Vulnerability patched (CVE-2024-1234 on web01)
        → Δ vulnerability processed
        → Derived facts with this vulnerability as sole derivation removed
        → Derived facts with alternative derivations unchanged
```

---

## 4. Technical Implementation Details

### 4.1 Arrangements (Indexed Collections)

For efficient joins, we pre-index collections:

```rust
// Create an arrangement (index) keyed by host
let vuln_by_host = vulnerabilities
    .map(|v| (v.host.clone(), v))
    .arrange_by_key();

// Now joins on host are O(log n) not O(n²)
exec_code.join_core(&vuln_by_host, |_key, exec, vuln| { ... })
```

### 4.2 Trace Sharing

Multiple operators can share the same indexed data:

```rust
let arranged = some_collection.arrange_by_key();

// Both rules use the same index, no duplication
let result1 = other1.join(&arranged);
let result2 = other2.join(&arranged);
```

### 4.3 Iteration (Fixpoint)

For transitive closure (attack propagation):

```rust
let reachable = roots.iterate(|reach| {
    let edges = edges.enter(&reach.scope());
    
    reach
        .map(|node| (node, ()))
        .join(&edges)            // Find neighbors
        .map(|(_, (_, dst))| dst)
        .concat(reach)           // Add to reachable set
        .distinct()              // Deduplicate
});
```

**Key Property**: Iteration terminates when no new changes occur (fixpoint).

---

## 5. Performance Characteristics

### 5.1 Time Complexity

| Operation | Complexity |
|-----------|------------|
| Insert/Delete base fact | O(log n) + O(affected derived facts) |
| Join | O(Δleft × matching_right + Δright × matching_left) |
| Iterate (per round) | O(Δ per round) until fixpoint |
| Full recomputation | O(n × m) for n facts, m rules |

### 5.2 Space Complexity

| Component | Space |
|-----------|-------|
| Base facts | O(n) |
| Arrangements (indexes) | O(n log n) per index |
| Trace history | O(updates) - configurable compaction |
| Derived facts | O(derived) |

### 5.3 Expected Performance for Attack Graphs

Based on differential dataflow benchmarks and attack graph characteristics:

| Network Size | Initial Computation | Incremental Update |
|--------------|--------------------|--------------------|
| 100 hosts | < 100ms | < 1ms |
| 1,000 hosts | < 1s | < 10ms |
| 10,000 hosts | < 30s | < 100ms |
| 100,000 hosts | < 10min | < 1s |

*These are estimates; actual performance depends on vulnerability density and network topology.*

---

## 6. Why Differential Dataflow for This Research?

### 6.1 Compared to Alternatives

| System | Incrementality | Open Source | Language | Distributed |
|--------|---------------|-------------|----------|-------------|
| **Differential Dataflow** | ✓ Native | ✓ MIT | Rust | ✓ |
| Soufflé | Partial (DRed) | ✓ UPL | C++ | ✗ |
| LogicBlox | ✓ | ✗ Commercial | LogiQL | ✓ |
| DDlog | ✓ Native | ✓ MIT | Rust | ✗ |
| Datomic | ✓ | ✗ Commercial | Clojure | ✓ |

### 6.2 Research Benefits

1. **Production-quality implementation**: Battle-tested at scale
2. **Principled design**: Based on formal semantics of differences
3. **Flexibility**: Can implement custom operators if needed
4. **Observability**: Can inspect intermediate states and differences
5. **Extensibility**: Easy to add new rules or modify existing ones

---

## 7. Next Steps

With this architecture in place, Phase 3 will implement:

1. **Schema Definition**: Rust structs for all fact types
2. **Rule Translation**: MulVAL rules → differential dataflow operators
3. **Input Simulation**: Create realistic network scenarios
4. **Update Demonstration**: Show incremental updates in action
5. **Benchmarking**: Measure actual performance characteristics
