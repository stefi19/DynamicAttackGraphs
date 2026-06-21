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
- Positive: Record is present with that multiplicity
- Zero: Record is absent
- Negative: Usually represents more deletions than insertions and should not
  persist for ordinary set-like input collections

For the attack graph rules in this project, the intended logical view is
set-like: a fact is present when its accumulated multiplicity is non-zero after
consolidation. Multiple derivations may contribute multiple positive
multiplicities internally, and retractions contribute negative multiplicities.
The accumulated value determines whether the record remains visible.

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
| Rederivation | Explicit second pass over threatened facts | Operators propagate signed differences |
| Multiple derivations | May be recovered during rederivation | Reflected by accumulated multiplicities |
| Project status | Not implemented directly | The implemented execution model |

DRed is an algorithm for maintaining a materialisation after deletions. It first
removes facts that may depend on deleted input, then tries to rederive facts
that still have valid proofs. Differential Dataflow does not implement this
overdelete-and-rederive procedure. Instead, each input change becomes a signed
difference, and the dataflow operators propagate the consequences of that
difference through the rule graph.

### Compared to B/F

| Aspect | B/F Algorithm | Differential Dataflow |
|--------|--------------|----------------------|
| Core deletion strategy | Backward proof checking plus forward propagation | Signed-difference propagation through operators |
| Alternate proofs | Checked by backward chaining before deletion is final | Represented indirectly by remaining positive multiplicity |
| Counting derivations | Not simply a counting algorithm | Uses diff/multiplicity arithmetic |
| When fact disappears | No alternate proof is found and consequences are propagated | Accumulated multiplicity reaches zero |
| Provenance | Reasoning process can inspect proofs | Not retained automatically by the diff stream |

B/F, as described by Motik et al., avoids DRed overdeletion by using backward
and forward chaining to check for alternate proofs. Differential Dataflow is
related because it also prevents unsupported records from remaining present
after updates, but it does so through diff accumulation rather than by directly
running B/F proof checks. The two should therefore be compared as different
incremental maintenance strategies, not treated as the same algorithm.

This prototype is a Differential Dataflow implementation of a subset of
MulVAL-style attack graph rules. It is not a direct B/F implementation, and it
does not expose a derivation-count table as its maintenance mechanism.

---

## 3. Terminology Accuracy

- **Materialisation**: The stored set of facts derived from the base facts and
  rules at a particular logical time.
- **Full recomputation**: Discarding the old dataflow state and rebuilding the
  derived facts from the updated base facts.
- **Incremental maintenance**: Updating the existing materialisation after a
  base fact changes, ideally doing work proportional to the affected region.
- **DRed**: Delete/Rederive maintenance. It may overdelete facts that could
  still have alternate proofs, then rederive the facts that remain valid.
- **B/F**: Backward/Forward maintenance. It uses backward chaining to check
  threatened facts for alternate proofs and forward chaining to propagate real
  consequences. It is not simply derivation counting.
- **Differential updates**: Signed changes that are propagated through
  Differential Dataflow operators. Accumulated multiplicity determines whether a
  record is present.
- **Provenance**: Information about why a derived fact holds. The current
  prototype reconstructs selected explanations separately; Differential
  Dataflow diffs do not by themselves provide a full proof tree. The current
  explainer returns one valid proof path for selected facts, including remote
  propagation and local privilege escalation; it does not enumerate all minimal
  attack paths.

---

## 4. Data Model

We model the attack graph with these collections:

```
BASE FACTS (Input):
  vulnerability    : (Host, CVE, Service, Privilege)
  local_vulnerability : (Host, CVE, Privilege)
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

## 5. Dataflow Pipeline

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
| Rule 4: Local privilege esc.     |
| non-root exec + local vuln       |
+----------------------------------+
       |
       v
+----------------------------------+
| Rule 5: Ownership and goals      |
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

## 6. Implementation Details

### Join Keys and Future Arrangements

The implementation keys joins by mapping records to suitable key-value pairs:

```rust
// Key vulnerabilities by host and service before joining.
let vulnerabilities_by_host_and_service = vulnerability_collection
    .map(|vuln| (vuln.host_name.clone(), vuln))
```

Differential Dataflow can also use explicit arrangements to reuse indexes across
operators. The current prototype relies on keyed joins directly; a future
optimization could introduce explicit arrangements where profiling shows
repeated index construction is material.

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

## 7. Performance

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

## 8. Why Differential Dataflow?

Compared to alternatives:

| System | Incrementality | Open Source | Distributed |
|--------|---------------|-------------|-------------|
| Differential Dataflow | Yes | Yes (MIT) | Yes |
| Souffle | High-performance Datalog baseline; incremental mode should be verified for the chosen release | Yes | No |
| LogicBlox | Incremental Datalog system; availability and licensing should be verified | No | Yes |
| DDlog | Incremental Datalog-derived system; project status should be verified | Yes | No |

We chose differential dataflow because:
- Native incrementality with counting semantics
- Open source implementation suitable for research prototyping
- Supports streaming updates
- Has a dataflow model that can scale beyond a single process, although this
  prototype currently benchmarks direct single-process execution
