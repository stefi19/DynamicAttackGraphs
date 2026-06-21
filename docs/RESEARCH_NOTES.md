# Research Notes: Dynamic Attack Graphs

## Summary

This project combines logic-based security analysis with incremental
computation. It is a research prototype that uses Differential Dataflow to
maintain a subset of MulVAL-style attack graph rules as network configurations
change.

---

## Key Findings

### 1. Why Datalog Works for Attack Graphs

| Requirement | Prolog | Datalog | Why It Matters |
|-------------|--------|---------|----------------|
| Termination guaranteed | Not in general | Yes, for function-free finite-domain programs | Security analysis must complete |
| Complete answer set | Depends on evaluation strategy | Yes, under bottom-up evaluation | All derived paths in the modeled rule subset must be found |
| Bottom-up evaluation | Not the default | Yes | Enables materialisation and incremental maintenance |
| Handles cycles | Requires care or tabling | Natural in bottom-up fixpoint evaluation | Networks have loops |
| Parallelizable | Hard | Easy | Scale to large networks |

### 2. Differential Dataflow vs Traditional Approaches

Traditional evaluated workflow (MulVAL/XSB Prolog):
```
Change fact -> Update inputs -> Re-run analysis -> full materialisation cost
```

Differential Dataflow:
```
Change fact -> Propagate signed diff -> Updated graph -> affected-region cost
```

### 3. The Gap We Address

| System | Incrementality | Open Source | Security Focus |
|--------|---------------|-------------|----------------|
| MulVAL | No dynamic incremental maintenance in the evaluated workflow | Yes | Yes |
| Souffle | High-performance Datalog baseline; incremental support should be verified separately | Yes | No |
| LogicBlox | Incremental Datalog system; availability and current licensing should be verified | No | No |
| This Project | Differential updates for implemented rule subset | Yes | Yes |

---

## Technical Architecture

### Data Flow

```
+----------------+
|  Fact Store    |
| (vulns,        |
|  network,      |
|  firewall)     |
+-------+--------+
        | changes as (data, time, diff)
        v
+------------------------------+
|    DIFFERENTIAL DATAFLOW     |
|  +------+  +------+  +-----+ |
|  | Map  |->| Join |->|Iter | |
|  +------+  +------+  +-----+ |
+------------------------------+
        | diffs only
        v
+----------------+
|   Outputs      |
| (execCode,     |
|  ownsMachine,  |
|  goalReached)  |
+----------------+
```

### Rule Translation Pattern

Datalog Rule:
```prolog
H(X,Y) :- A(X,Z), B(Z,Y).
```

Differential Dataflow:
```rust
let h = a
    .map(|(x, z)| (z, x))      // Key by join variable
    .join(&b.map(|(z, y)| (z, y)))
    .map(|(z, (x, y))| (x, y)); // Project result
```

---

## Implementation Details

### Schema Design

We use a normalized relational schema matching MulVAL's predicates:

```rust
// Base facts (input)
struct VulnerabilityRecord { host_name, vulnerability_id, affected_service, privilege_gained }
struct LocalVulnerabilityRecord { host_name, vulnerability_id, privilege_gained_on_exploit }
struct NetworkAccessRule { source_host, destination_host, service_name }
struct FirewallRuleRecord { source_zone, destination_host, service_name, rule_action }
struct AttackerStartingPosition { attacker_id, starting_host, initial_privilege }
struct AttackerTargetGoal { attacker_id, target_host_name }

// Derived facts (output)
struct AttackerCodeExecution { attacker_id, compromised_host, obtained_privilege }
struct AttackerOwnsMachine { attacker_id, owned_host }
struct AttackerGoalReached { attacker_id, reached_target }
```

### Rule Implementation

The main recursive rule:

```rust
let all_code_executions = initial_code_execution.iterate(|current_executions| {
    // Bring collections into iteration scope
    let access_in_scope = network_access_by_source.enter(&current_executions.scope());
    let vulns_in_scope = vulnerabilities_by_host_and_service.enter(&current_executions.scope());
    
    // Find reachable hosts from current positions
    let reachable = current_executions
        .map(|exec| (exec.compromised_host, exec.attacker_id))
        .join(&access_in_scope);
    
    // Join with vulnerabilities to get new executions
    let new_executions = reachable
        .map(|(_, (attacker, (dest, service)))| ((dest, service), attacker))
        .join(&vulns_in_scope)
        .map(|((host, _), (attacker, priv))| AttackerCodeExecution { ... });
    
    // Combine and deduplicate
    new_executions.concat(current_executions).distinct()
});
```

---

## Implemented Research Support

Current support includes:

1. Differential Dataflow rules for recursive remote exploitation, stratified
   firewall deny rules, local privilege escalation, ownership, and goal reachability.
2. A naive HashSet fixpoint evaluator for small-scenario correctness checks.
3. A MulVAL-like `.facts` parser and example scenario files.
4. Incremental-vs-recompute correctness tests and naive-oracle equivalence tests.
5. Full recomputation-after-update benchmark baselines.
6. CSV benchmark export for paper tables and plots.
7. Layered enterprise synthetic scenarios in addition to star and chain topologies.
8. A provenance layer that reconstructs one selected explanation tree after
   computation and can export it to Graphviz DOT.

## Test Results

From our demonstration:

| Phase | Operation | Time |
|-------|-----------|------|
| 1 | Initial computation | ~1.2ms |
| 2 | Add firewall rule | ~0.3ms |
| 3 | Patch vulnerability | ~0.15ms |
| 4 | New vulnerability discovered | ~0.2ms |

These demonstration timings compare updates against the initial run. Research
claims should use the full recomputation-after-update benchmark baseline.

---

## Future Work

1. Scale testing with larger and more realistic enterprise scenarios.
2. Compare with high-performance Datalog baselines such as Souffle after
   verifying the relevant incremental evaluation mode.
3. Add broader MulVAL rule coverage and more precise CVE semantics.
4. Integrate with real vulnerability scanner and asset inventory data.
5. Extend provenance to enumerate alternative or minimal explanations, rather
   than reconstructing one valid selected path.

---

## References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
3. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993.
4. Motik, B., et al. "Incremental Update of Datalog Materialization." AAAI 2015.
