# Research Notes: Dynamic Attack Graphs

## Summary

This project combines logic-based security analysis with incremental computation. We use differential dataflow to maintain attack graphs in real-time as network configurations change.

---

## Key Findings

### 1. Why Datalog Works for Attack Graphs

| Requirement | Prolog | Datalog | Why It Matters |
|-------------|--------|---------|----------------|
| Termination guaranteed | No | Yes | Security analysis must complete |
| Complete answer set | No | Yes | All attack paths must be found |
| Bottom-up evaluation | No | Yes | Enables incrementality |
| Handles cycles | Problematic | Natural | Networks have loops |
| Parallelizable | Hard | Easy | Scale to large networks |

### 2. Differential Dataflow vs Traditional Approaches

Traditional (MulVAL/XSB Prolog):
```
Change fact -> Retract -> Re-run full analysis -> 10s-minutes
```

Differential Dataflow:
```
Change fact -> Propagate diff -> Updated graph -> milliseconds
```

### 3. The Gap We Address

| System | Incrementality | Open Source | Security Focus |
|--------|---------------|-------------|----------------|
| MulVAL | None | Yes | Yes |
| Souffle | DRed (partial) | Yes | No |
| LogicBlox | Full | No | No |
| This Project | Full | Yes | Yes |

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

## Test Results

From our demonstration:

| Phase | Operation | Time |
|-------|-----------|------|
| 1 | Initial computation | ~1.2ms |
| 2 | Add firewall rule | ~0.3ms |
| 3 | Patch vulnerability | ~0.15ms |
| 4 | New CVE discovered | ~0.2ms |

Incremental updates are 5-10x faster than initial computation.

---

## Future Work

1. Scale testing with larger networks (1K-100K hosts)
2. Compare with Souffle's DRed implementation
3. Add support for more complex attack patterns
4. Integrate with real vulnerability scanners
5. Visualization of attack paths

---

## References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
3. Gupta, A., et al. "Maintaining Views Incrementally." SIGMOD 1993.
4. Motik, B., et al. "Incremental Update of Datalog Materialization." AAAI 2015.
