# Phase 1: Conceptual Framework

## Dynamic Attack Graphs using Differential Dataflow

This document provides the theoretical foundation for our research project on Dynamic Attack Graphs. We address the key questions about why certain technologies and algorithms are preferred for this specific use case.

---

## 1. Why Datalog over Prolog for Attack Graphs?

### 1.1 The Core Problem

Attack graph generation requires computing all possible attack paths through a network. This is fundamentally a **fixpoint computation**: we repeatedly derive new facts (possible compromises) from existing facts (vulnerabilities, network topology) until no new facts can be derived.

### 1.2 Prolog's Limitations

Prolog uses **top-down evaluation** with **SLD resolution** (Selective Linear Definite clause resolution):

```prolog
% Prolog: May not terminate!
reachable(X, Y) :- connected(X, Y).
reachable(X, Y) :- connected(X, Z), reachable(Z, Y).

% Query: ?- reachable(a, X).
% Risk: Infinite loop if graph has cycles
```

**Problems for Attack Graphs:**

1. **Non-termination**: Cyclic attack paths can cause infinite loops
2. **Order-dependent**: Results depend on clause ordering
3. **Incomplete**: May miss valid derivations due to depth-first search
4. **No natural support for updates**: Retraction and re-computation is expensive

### 1.3 Datalog's Advantages

Datalog uses **bottom-up evaluation** with **semi-naive evaluation**:

```datalog
% Datalog: Always terminates!
reachable(X, Y) :- connected(X, Y).
reachable(X, Y) :- connected(X, Z), reachable(Z, Y).

% Computes ALL reachable pairs, terminates when fixpoint reached
```

**Advantages for Attack Graphs:**

| Property | Prolog | Datalog |
|----------|--------|---------|
| **Termination** | Not guaranteed | Always terminates (finite Herbrand base) |
| **Completeness** | May miss answers | Computes minimal model |
| **Evaluation** | Top-down, goal-driven | Bottom-up, data-driven |
| **Cycles** | Problematic | Handled naturally |
| **Parallelization** | Difficult | Natural (join operations) |
| **Incrementality** | Hard to implement | Well-studied algorithms |

### 1.4 Why This Matters for MulVAL

MulVAL (Multi-host, Multi-stage Vulnerability Analysis Language) uses Datalog precisely because:

1. **Complete enumeration**: We need ALL attack paths, not just one
2. **Transitive closure**: Attack propagation is inherently recursive
3. **Guaranteed termination**: Security analysis must complete
4. **Declarative semantics**: Rules directly map to security concepts

```datalog
% MulVAL-style rule: Transitive access propagation
execCode(Attacker, Host2, Priv) :-
    execCode(Attacker, Host1, _),
    accessEnabled(Host1, Host2, Protocol),
    vulExists(Host2, VulnID, Protocol),
    vulProperty(VulnID, remoteExploit, privEscalation).
```

---

## 2. DRed vs Backward/Forward (B/F) Algorithm

### 2.1 The Incremental Update Problem

When facts change in a Datalog database, we have two options:
1. **Re-compute everything**: Simple but expensive O(full computation)
2. **Incremental update**: Only compute changes O(size of change)

### 2.2 DRed (Delete/Rederive) Algorithm

**Overview**: DRed handles deletions by:
1. **Delete phase**: Remove all facts that *might* be affected (over-approximation)
2. **Rederive phase**: Re-derive facts that are still valid

```
DRed Algorithm:
─────────────────────────────────────────────────────
Input: Database D, deleted facts Δ⁻

Phase 1 (Over-delete):
  affected = Δ⁻
  while affected not empty:
    for each rule r with body containing facts from affected:
      mark head(r) as potentially deleted
      add head(r) to affected

Phase 2 (Rederive):
  for each potentially deleted fact f:
    if f can be re-derived from remaining facts:
      restore f
─────────────────────────────────────────────────────
```

**Characteristics:**
- Simple to implement
- May do redundant work (delete then re-derive the same fact)
- Works well when deletions don't cascade far
- Widely implemented (e.g., in Soufflé with `-DUSE_PROVENANCE`)

### 2.3 Backward/Forward (B/F) Algorithm

**Overview**: The B/F algorithm is more sophisticated:

```
B/F Algorithm:
─────────────────────────────────────────────────────
Input: Database D, changes Δ (insertions and deletions)

Phase 1 (Backward - Counting):
  For each derived fact, maintain a COUNT of derivations
  When a base fact is deleted:
    Decrement counts of all facts derived using it
    If count reaches 0, fact is truly deleted

Phase 2 (Forward - Propagation):
  For insertions: derive new facts (standard semi-naive)
  For deletions with count=0: propagate deletion forward
─────────────────────────────────────────────────────
```

**Key Insight**: B/F maintains **derivation counts** (or full provenance), avoiding the over-deletion problem of DRed.

### 2.4 Comparison Table

| Aspect | DRed | B/F Algorithm |
|--------|------|---------------|
| **Deletion handling** | Over-delete + rederive | Count-based precise deletion |
| **Space overhead** | Minimal | Requires derivation counts/provenance |
| **Worst-case time** | Can re-derive entire database | Proportional to actual changes |
| **Redundant work** | Yes (may delete valid facts) | No (precise tracking) |
| **Implementation complexity** | Simpler | More complex |
| **Cascading deletions** | Expensive | Efficient |

---

## 3. The Research Gap: Why B/F for Security Attack Graphs?

### 3.1 Characteristics of Attack Graph Workloads

Attack graphs have unique properties that make B/F potentially superior:

1. **High interconnectivity**: Networks are often densely connected
2. **Cascading dependencies**: One vulnerability enables many attacks
3. **Frequent small updates**: 
   - Firewall rules change
   - Services start/stop
   - Vulnerabilities patched
   - New CVEs discovered

4. **Large derivation fan-out**: A single `execCode` fact may enable hundreds of derived attacks

### 3.2 Why DRed Struggles with Attack Graphs

Consider this scenario:

```
Initial state:
  vulnExists(webServer, CVE-2024-1234, http) 
  → enables execCode(attacker, webServer, user)
  → enables 50 lateral movement paths
  → enables 200 privilege escalation paths

Update: Patch CVE-2024-1234 (delete vulnerability)

DRed behavior:
  1. Delete vulnExists(webServer, CVE-2024-1234, http)
  2. Over-delete: Mark 251 derived facts as "potentially deleted"
  3. Rederive: Check each of the 251 facts
     - Many may still be derivable via OTHER vulnerabilities!
     - Redundant work for facts with multiple derivations
```

### 3.3 Why B/F is Better for Attack Graphs

```
B/F behavior:
  1. Delete vulnExists(webServer, CVE-2024-1234, http)
  2. Decrement derivation counts for dependent facts
  3. Only facts with count=0 are actually deleted
  4. No redundant rederivation!

Space trade-off: Store derivation count per fact
Time benefit: O(actually deleted facts) vs O(all potentially affected)
```

### 3.4 The Specific Research Gap

**Current State of the Art:**
- MulVAL: Uses XSB Prolog, no incremental support
- Most attack graph tools: Re-compute from scratch on changes
- Soufflé: Has DRed-based incrementality, but not optimized for security workloads
- LogicBlox/Datomic: Commercial, closed-source

**The Gap:**
1. **No open-source implementation** of B/F-style incremental update for attack graphs
2. **No empirical comparison** of DRed vs B/F on realistic security workloads
3. **No integration** with modern streaming/reactive architectures

**Our Contribution:**
Using **Differential Dataflow** as a practical implementation vehicle because:
- It provides counting-based incrementality (similar to B/F spirit)
- It's open-source and production-ready
- It supports streaming updates naturally
- It scales to distributed computation

---

## 4. Formal Properties We Want to Preserve

### 4.1 Soundness
Every derived attack path must be valid:
```
∀ path ∈ AttackGraph: path is realizable given current network state
```

### 4.2 Completeness
All possible attack paths are found:
```
∀ realizable path: path ∈ AttackGraph
```

### 4.3 Incrementality
Updates are efficient:
```
Time(update) = O(|Δoutput|) not O(|fullGraph|)
```

### 4.4 Monotonicity of Outputs
For a monotonic Datalog program (no negation):
```
If facts only increase → derived facts only increase
If facts decrease → derived facts can only decrease or stay same
```

---

## 5. Research Questions

Based on this conceptual framework, our key research questions are:

1. **RQ1**: How does differential dataflow's approach compare to classical B/F on attack graph workloads?

2. **RQ2**: What is the practical overhead of maintaining provenance/counts for large attack graphs?

3. **RQ3**: Can we achieve sub-second update times for realistic enterprise networks (10K+ hosts)?

4. **RQ4**: How do different update patterns (patch waves, configuration changes, new CVEs) affect incremental performance?

---

## References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993. (DRed algorithm)
3. Motik, B., et al. "Incremental Update of Datalog Materialization." AAAI 2015. (B/F improvements)
4. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
5. Ryzhyk, L., Budiu, M. "Differential Datalog." Datalog 2019.
