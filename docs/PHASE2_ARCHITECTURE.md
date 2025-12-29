# Phase 2: Architecture

## Differential Dataflow for Dynamic Attack Graphs

This document explains how differential dataflow handles incremental updates.

---

## 1. Core Concepts

### The (data, time, diff) Tuple

Differential dataflow represents all data as a stream of changes:

```rust
(data: D, time: T, diff: R)
```

Where:
- `data` - The actual record (e.g., a vulnerability or attack path)
- `time` - A logical timestamp (version of the database)
- `diff` - A difference value (+1 for insertion, -1 for deletion)

Example:

```rust
// At time 0: Insert a vulnerability
(Vulnerability { host: "web01", cve: "CVE-2024-1234" }, time: 0, diff: +1)

// At time 5: Patch the vulnerability (remove it)
(Vulnerability { host: "web01", cve: "CVE-2024-1234" }, time: 5, diff: -1)
```

### Collections as Multisets

A collection at any time t is the sum of all diffs up to that time:

```
Collection[t] = sum of all (data, diff) where time <= t
```

If the sum for a record is:
- Positive: Record is present
- Zero: Record is absent

### Operators Work on Differences

All operators (map, filter, join, reduce) work on differences, not full collections:

```rust
// For joins:
output_diff = (left_diff join right) + (left join right_diff) + (left_diff join right_diff)
```

This is the key insight: we only process changes, not the full data.

---

## 2. Relation to DRed and B/F

### Compared to DRed

| Aspect | DRed | Differential Dataflow |
|--------|------|----------------------|
| Deletion handling | Over-delete, then rederive | Changes cancel mathematically |
| Rederivation | Explicit second pass | Implicit through diff arithmetic |
| Multiple derivations | Must track and re-check | Diffs accumulate naturally |

### Compared to B/F

| Aspect | B/F Algorithm | Differential Dataflow |
|--------|--------------|----------------------|
| Counting derivations | Explicit count per fact | Implicit in diff accumulation |
| When fact disappears | Count reaches 0 | Sum of diffs reaches 0 |
| Provenance | Stored separately | Encoded in the diff stream |

Both approaches use counting to determine when a derived fact should be removed. B/F counts explicitly; differential dataflow achieves the same through diff arithmetic.

---

## 3. Data Model

We model the attack graph with these collections:

```
BASE FACTS (Input):
  vulnerability    : (Host, CVE, Service, Privilege)
  network_access   : (SrcHost, DstHost, Service)
  firewall_rule    : (Src, Dst, Service, Action)
  attacker_located : (Attacker, Host, Privilege)
  attacker_goal    : (Attacker, TargetHost)

DERIVED FACTS (Output):
  effective_access : (Src, Dst, Service)
  exec_code        : (Attacker, Host, Privilege)
  owns_machine     : (Attacker, Host)
  goal_reached     : (Attacker, Target)
```

---

## 4. Dataflow Pipeline

```
Input Collections
       |
       v
+----------------------------------+
| Rule 1: Compute effective access |
| effective_access = network_access|
|                    - blocked     |
+----------------------------------+
       |
       v
+----------------------------------+
| Rule 2: Initial code execution   |
| from attacker starting positions |
+----------------------------------+
       |
       v
+----------------------------------+
| Rule 3: Transitive propagation   |
| (uses iterate for fixpoint)      |
+----------------------------------+
       |
       v
+----------------------------------+
| Rule 4: Privilege escalation     |
| owns_machine if has root         |
+----------------------------------+
       |
       v
Output Collections
```

### Handling Updates

When a fact changes, only affected parts are recomputed:

```
Time 0: Initial network state
        -> Full computation, establish baseline

Time 1: Firewall rule added
        -> Only recompute affected paths

Time 2: Vulnerability patched
        -> Remove derived facts that depended on it
        -> Facts with other derivations remain unchanged
```

---

## 5. Implementation Details

### Arrangements (Indexed Collections)

For efficient joins, we pre-index collections:

```rust
// Index vulnerabilities by host
let vulnerabilities_by_host = vulnerability_collection
    .map(|vuln| (vuln.host_name.clone(), vuln))
    .arrange_by_key();

// Joins on host are now O(log n) not O(n^2)
```

### Iteration for Fixpoint

For transitive closure (attack propagation):

```rust
let all_executions = initial.iterate(|current| {
    let edges = network_access.enter(&current.scope());
    
    current
        .join(&edges)        // Find neighbors
        .concat(current)     // Add to set
        .distinct()          // Remove duplicates
});
```

Iteration stops when no new changes occur.

---

## 6. Performance

### Time Complexity

| Operation | Complexity |
|-----------|------------|
| Insert/Delete base fact | O(log n) + O(affected derived facts) |
| Join | O(size of changes) |
| Iterate | O(changes per round) until fixpoint |

### Expected Performance

| Network Size | Initial Computation | Incremental Update |
|--------------|--------------------|--------------------|
| 100 hosts | < 100ms | < 1ms |
| 1,000 hosts | < 1s | < 10ms |
| 10,000 hosts | < 30s | < 100ms |

Actual performance depends on vulnerability density and network topology.

---

## 7. Why Differential Dataflow?

Compared to alternatives:

| System | Incrementality | Open Source | Distributed |
|--------|---------------|-------------|-------------|
| Differential Dataflow | Yes | Yes (MIT) | Yes |
| Souffle | Partial (DRed) | Yes | No |
| LogicBlox | Yes | No (Commercial) | Yes |
| DDlog | Yes | Yes (MIT) | No |

We chose differential dataflow because:
- Native incrementality with counting semantics
- Open source and production-ready
- Supports streaming updates
- Scales to distributed computation
