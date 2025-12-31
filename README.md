# Dynamic Attack Graphs using Differential Dataflow

**Incremental computation of security attack graphs using Rust and differential dataflow.**

This project demonstrates that patching a single vulnerability in a 1000-node network updates the attack graph in **160 microseconds** instead of 4 milliseconds — a **25x speedup** over full recomputation.

---

## 🚀 Quick Start (Docker - Recommended)

**One command to see benchmark results:**

```bash
docker build -t attack-graph .
docker run --rm attack-graph
```

This runs the full benchmark suite and shows speedup tables like:

```
| Nodes | Initial (ms) | Incremental (us) | Speedup |
|------:|-------------:|-----------------:|--------:|
|    51 |         1.58 |           501.08 |    3.2x |
|   101 |         1.96 |           413.25 |    4.7x |
|   501 |         3.48 |           281.58 |   12.4x |
|  1001 |         4.11 |           160.88 |   25.6x |  <-- ⭐
```

---

## 📊 Visualizing Attack Graphs

Generate before/after images showing how patching breaks attack paths:

```bash
# Run the visualization example
cargo run --release --example graphviz_export

# Convert to PNG (requires graphviz)
dot -Tpng graph_initial.dot -o graph_initial.png
dot -Tpng graph_final.dot -o graph_final.png

# Or use the helper script
./generate_graphs.sh
```

**Result:** Two images showing the attack path in red, then disappearing after the patch.

| Before Patch | After Patch |
|:---:|:---:|
| ![Initial](graph_initial.png) | ![Final](graph_final.png) |

**Legend:**
- 🔵 Blue: Attacker starting position
- 🟠 Orange: Compromised nodes
- 🔴 Red: Target compromised
- 🟢 Green: Target safe
- Red edges: Active attack path

---

## 🛠 Local Development

### Requirements

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- Graphviz (optional, for visualization): `brew install graphviz`

### Build and Run

```bash
# Build
cargo build --release

# Run main demo
cargo run --release

# Run benchmarks
cargo run --release --example run_benchmarks

# Run simple example
cargo run --release --example simple_demo

# Run visualization export
cargo run --release --example graphviz_export
```

---

## 📈 Benchmark Results

See [BENCHMARKS.md](BENCHMARKS.md) for detailed analysis.

### Summary

| Topology | Change Type | Speedup |
|----------|-------------|---------|
| Star (1000 nodes) | Patch 1 leaf | **25x** |
| Chain (random cut) | Patch random node | **2x average** |
| Chain (worst case) | Patch at start | 1x (expected) |

**Key insight:** Incremental update complexity is O(affected nodes), not O(total nodes).

---

## 🏗 Architecture

```
+-----------------------------------------------------------+
|                     INPUT FACTS                           |
+-----------------------------------------------------------+
|  vulnerabilities  : (Host, CVE, Service, Privilege)       |
|  network_access   : (Source, Destination, Service)        |
|  firewall_rules   : (Src, Dst, Service, Action)           |
|  attacker_start   : (Attacker, Host)                      |
+-----------------------------------------------------------+
                              |
                    Differential Dataflow
                   (incremental maintenance)
                              |
                              v
+-----------------------------------------------------------+
|                    DERIVED FACTS                          |
+-----------------------------------------------------------+
|  execCode      : (Attacker, Host, Privilege)              |
|  ownsMachine   : (Attacker, Host)                         |
|  goalReached   : (Attacker, Target)                       |
+-----------------------------------------------------------+
```

When any input changes, only affected derived facts are recomputed.

---

## 📂 Project Structure

```
src/
  schema.rs      - Data type definitions
  rules.rs       - Attack graph inference rules
  benchmarks.rs  - Performance measurement code
  main.rs        - Main demonstration
  lib.rs         - Library exports

examples/
  run_benchmarks.rs   - Full benchmark suite
  graphviz_export.rs  - Visual graph generation
  simple_demo.rs      - Minimal working example

paper/
  main.tex       - LaTeX research paper
  references.bib - Bibliography

docs/
  PHASE1_CONCEPTUAL_FRAMEWORK.md
  PHASE2_ARCHITECTURE.md
```

---

## 📄 Documentation

- [BENCHMARKS.md](BENCHMARKS.md) - Detailed benchmark results and analysis
- [docs/PHASE1_CONCEPTUAL_FRAMEWORK.md](docs/PHASE1_CONCEPTUAL_FRAMEWORK.md) - Theory background
- [docs/PHASE2_ARCHITECTURE.md](docs/PHASE2_ARCHITECTURE.md) - Implementation details
- [paper/main.tex](paper/main.tex) - LaTeX research paper

---

## 🔬 How It Works

### MulVAL-style Rule (Datalog)
```prolog
execCode(Attacker, Host, Priv) :-
    execCode(Attacker, SrcHost, _),
    netAccess(SrcHost, Host, Service),
    vulExists(Host, _, Service, Priv).
```

### Differential Dataflow Translation (Rust)
```rust
let reachable = initial_positions.iterate(|inner| {
    inner
        .join(&network_access)      // Find where attacker can go
        .semijoin(&vulnerabilities) // Keep only vulnerable targets
        .concat(inner)              // Add to existing reachable set
        .distinct()                 // Remove duplicates
});
```

When a vulnerability is removed, the `semijoin` propagates the deletion through the dataflow graph, removing all dependent attack paths automatically.

---

## 📚 References

1. Ou, X., et al. "MulVAL: A Logic-based Network Security Analyzer." USENIX Security 2005.
2. McSherry, F., et al. "Differential Dataflow." CIDR 2013.
3. Murray, D., et al. "Naiad: A Timely Dataflow System." SOSP 2013.

---

## 📜 License

MIT License
