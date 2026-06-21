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

Problems for naive top-down evaluation:
1. Cyclic attack paths can cause infinite loops
2. Results depend on clause ordering
3. Naive top-down Prolog evaluation can be sensitive to recursion, clause
   ordering, and termination unless tabling or other mechanisms are used
4. Dynamic incremental maintenance is not part of the standard MulVAL workflow

### Datalog's Advantages

Datalog uses bottom-up evaluation:

```datalog
% Function-free Datalog over finite domains terminates under bottom-up evaluation
reachable(X, Y) :- connected(X, Y).
reachable(X, Y) :- connected(X, Z), reachable(Z, Y).
```

Comparison:

| Property | Prolog | Datalog |
|----------|--------|---------|
| Termination | Not guaranteed for naive top-down recursion | Terminates for function-free finite-domain programs |
| Completeness | Depends on evaluation strategy and tabling | Computes the least fixpoint under bottom-up evaluation |
| Cycles | Require care | Handled naturally by fixpoint evaluation |
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
- It deliberately overdeletes. Any fact that may depend on a removed fact is
  removed, even if it also has an independent proof.
- It may then rederive the same fact during the second phase.
- The redundant work can be large when deletions affect a dense or recursive
  region of the materialisation.

### Backward/Forward (B/F) Algorithm

B/F is more selective than DRed. In the Motik et al. algorithm, deletion
handling uses backward chaining to ask whether a threatened fact still has an
alternative proof, and forward chaining to propagate consequences where no
alternative proof exists.

```
When a base fact is deleted:
  Identify facts whose known derivation may be invalid
  Use backward chaining to search for alternate proofs
  Use forward chaining to propagate only the facts that really disappear
```

Key insight: B/F avoids DRed-style overdeletion by checking whether threatened
facts can still be proved. It should not be described simply as a
derivation-counting algorithm.

### Derivation Counting

Derivation counting is a different incremental maintenance technique. It keeps
the number of current derivations for each fact and removes a fact only when the
count falls to zero. This is a useful point of comparison because it also
preserves facts with alternate derivations, but it is not the same algorithm as
B/F.

Differential Dataflow uses signed differences, or multiplicities, in its
collections. When the accumulated multiplicity of a record is positive, the
record is present; when it reaches zero, the record is absent. This is closer to
implicit multiplicity tracking than to a direct implementation of B/F.

This project implements MulVAL-style attack graph rules in Differential
Dataflow. It does not directly implement DRed, B/F, or an explicit
derivation-counting maintenance algorithm.

### Comparison

| Aspect | DRed | B/F Algorithm | Differential Dataflow in this project |
|--------|------|---------------|----------------------------------------|
| Deletion handling | Over-delete + rederive | Backward proof search + forward propagation | Signed diff propagation through dataflow operators |
| Alternate derivations | Recovered during rederivation | Checked before deleting threatened facts | Reflected through accumulated multiplicities |
| Counting model | Not the core idea | Not simply derivation counting | Uses implicit record multiplicities |
| Implementation in this project | Not implemented directly | Not implemented directly | Implemented rule engine |

---

## 3. Why This Research Matters

### Attack Graph Characteristics

Attack graphs have properties that make precise incremental maintenance useful:
1. Networks are often densely connected
2. One vulnerability enables many attack paths
3. Frequent small updates (patches, firewall changes, new CVEs)

### The Research Gap

Current state:
- MulVAL uses XSB Prolog with tabling, but the standard evaluated workflow does
  not provide Differential Dataflow-style dynamic maintenance after base-fact
  updates
- Most attack graph workflows re-compute from scratch on changes
- There are few open research prototypes evaluating differential incremental
  maintenance for MulVAL-style attack graph rules

Our contribution:
- Using differential dataflow as a practical implementation
- It provides incremental maintenance through differential updates and
  multiplicity arithmetic
- It is an open-source research prototype
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

1. Can MulVAL-style attack graph rules be expressed using Differential Dataflow operators?
2. How much faster are incremental updates than full recomputation?
3. Can we achieve sub-second updates for enterprise networks (10K+ hosts)?
4. How do different update patterns affect performance?

---

## References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993.
3. Motik, B., et al. "Incremental Update of Datalog Materialization." AAAI 2015.
4. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
