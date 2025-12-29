# Phase 1: Conceptual Framework

## Dynamic Attack Graphs using Differential Dataflow

This document explains the theory behind the project.

---

## 1. Why Datalog over Prolog for Attack Graphs?

### The Problem

Attack graph generation requires computing all possible attack paths through a network. This is a fixpoint computation: we derive new facts from existing facts until nothing new can be derived.

### Prolog's Limitations

Prolog uses top-down evaluation with SLD resolution:

```prolog
% Prolog can get stuck in infinite loops with cycles
reachable(X, Y) :- connected(X, Y).
reachable(X, Y) :- connected(X, Z), reachable(Z, Y).
```

Problems for attack graphs:
1. Cyclic attack paths can cause infinite loops
2. Results depend on clause ordering
3. May miss valid derivations due to depth-first search
4. No natural support for incremental updates

### Datalog's Advantages

Datalog uses bottom-up evaluation:

```datalog
% Datalog always terminates
reachable(X, Y) :- connected(X, Y).
reachable(X, Y) :- connected(X, Z), reachable(Z, Y).
```

Comparison:

| Property | Prolog | Datalog |
|----------|--------|---------|
| Termination | Not guaranteed | Always terminates |
| Completeness | May miss answers | Computes all answers |
| Cycles | Problematic | Handled naturally |
| Parallelization | Difficult | Natural |
| Incrementality | Hard to implement | Well-studied |

### Why This Matters for MulVAL

MulVAL uses Datalog because:
1. We need ALL attack paths, not just one
2. Attack propagation is recursive
3. Security analysis must complete
4. Rules directly map to security concepts

---

## 2. DRed vs Backward/Forward Algorithm

### The Incremental Update Problem

When facts change, we can either:
1. Re-compute everything (simple but slow)
2. Compute only the changes (fast but complex)

### DRed (Delete/Rederive) Algorithm

DRed handles deletions in two phases:

```
Phase 1 (Over-delete):
  Mark all facts that MIGHT be affected as deleted

Phase 2 (Rederive):
  Check each marked fact - if it can still be derived, restore it
```

Problems:
- May do redundant work (delete then re-derive the same fact)
- Works well only when deletions don't cascade far

### Backward/Forward (B/F) Algorithm

B/F is more sophisticated:

```
For each derived fact, keep a COUNT of how many ways it can be derived

When a base fact is deleted:
  Decrement counts of affected facts
  Only delete facts where count reaches 0
```

Key insight: B/F uses derivation counts to avoid over-deletion.

### Comparison

| Aspect | DRed | B/F Algorithm |
|--------|------|---------------|
| Deletion handling | Over-delete + rederive | Count-based precise deletion |
| Space overhead | Minimal | Requires derivation counts |
| Redundant work | Yes | No |
| Implementation | Simpler | More complex |

---

## 3. Why This Research Matters

### Attack Graph Characteristics

Attack graphs have properties that make B/F-style updates better:
1. Networks are often densely connected
2. One vulnerability enables many attack paths
3. Frequent small updates (patches, firewall changes, new CVEs)

### The Research Gap

Current state:
- MulVAL uses XSB Prolog with no incremental support
- Most tools re-compute from scratch on changes
- No open implementation of efficient incremental updates for attack graphs

Our contribution:
- Using differential dataflow as a practical implementation
- It provides counting-based incrementality
- It's open-source and production-ready
- It supports streaming updates

---

## 4. Properties We Want

### Soundness
Every derived attack path must be valid given current network state.

### Completeness
All possible attack paths must be found.

### Incrementality
Update time should be proportional to the size of changes, not the full graph.

---

## 5. Research Questions

1. How does differential dataflow compare to DRed on attack graph workloads?
2. What is the overhead of maintaining derivation counts for large attack graphs?
3. Can we achieve sub-second updates for enterprise networks (10K+ hosts)?
4. How do different update patterns affect performance?

---

## References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993.
3. Motik, B., et al. "Incremental Update of Datalog Materialization." AAAI 2015.
4. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
