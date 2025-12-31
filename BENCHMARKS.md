# Benchmark Results: Dynamic Attack Graphs with Differential Dataflow

This document presents benchmark results demonstrating the efficiency of incremental computation for dynamic attack graphs using differential dataflow.

## Overview

We evaluate three network topologies to demonstrate different aspects of incremental computation:

1. **Star Network** - Best case: O(1) iteration depth
2. **Chain Network** - Worst case: O(N) iteration depth  
3. **Chain Random Cut** - Shows position-dependent speedup

All benchmarks compare:
- **Initial computation**: Building the attack graph from scratch
- **Incremental update**: Updating after a small change (patching one vulnerability)

## Test Environment

- **Framework**: differential-dataflow v0.12 + timely v0.12
- **Language**: Rust (release mode, optimized)
- **Execution**: Single-threaded (`execute_directly`)

---

## Part 1: Star Network Benchmarks

### Topology Description

```
        [leaf_0]
            |
        [leaf_1]
            |
[hub] ------+------ [leaf_2]
            |
        [leaf_3]
            |
          ...
```

- **Structure**: Central hub connected to N leaves
- **Attacker start**: Hub node
- **Goal**: All leaf nodes
- **Change tested**: Patch vulnerability on one leaf

### Why Star Performs Well

The star topology has **O(1) iteration depth** - the attack graph converges in a constant number of iterations regardless of size. When we patch one leaf, only that leaf's attack path is affected.

### Results

| Nodes | Initial (ms) | Incremental (µs) | Speedup |
|------:|-------------:|-----------------:|--------:|
| 51    | 1.58         | 501.08           | 3.2x    |
| 101   | 1.96         | 413.25           | 4.7x    |
| 201   | 1.97         | 349.25           | 5.6x    |
| 501   | 3.48         | 281.58           | 12.4x   |
| 1001  | 4.11         | 160.88           | 25.6x   |

### Key Observations

1. **Initial computation scales linearly** with network size (~4ms for 1000 nodes)
2. **Incremental update stays nearly constant** (~160-500µs regardless of size)
3. **Speedup increases with size** - from 3x at 51 nodes to **25x at 1001 nodes**

### Interpretation for Paper

> "For star topologies, incremental computation achieves O(1) update complexity. At 1000 nodes, patching a single vulnerability requires only 160µs compared to 4.1ms for full recomputation - a 25x speedup."

---

## Part 2: Chain Network Benchmarks

### Topology Description

```
[node_0] -> [node_1] -> [node_2] -> ... -> [node_N-1]
```

- **Structure**: Linear chain of N nodes
- **Attacker start**: node_0
- **Goal**: node_N-1 (last node)
- **Change tested**: Patch vulnerability on node_1 (near the start)

### Why Chain is Worst Case

The chain topology has **O(N) iteration depth** - information must propagate through N nodes. When we patch node_1, all nodes from node_1 to node_N-1 lose their attack paths.

### Results

| Nodes | Initial (ms) | Incremental (µs) | Speedup |
|------:|-------------:|-----------------:|--------:|
| 10    | 0.87         | 833.04           | 1.0x    |
| 50    | 3.61         | 2506.62          | 1.4x    |
| 100   | 6.26         | 5196.67          | 1.2x    |
| 200   | 9.73         | 8923.12          | 1.1x    |

### Key Observations

1. **Both initial and incremental scale linearly** with chain length
2. **Speedup is minimal (~1x)** because patching near the start invalidates the entire chain
3. This is the **theoretical worst case** for incremental computation

### Interpretation for Paper

> "Chain topologies represent the worst case where a single change can invalidate O(N) derived facts. Even here, incremental computation performs comparably to full recomputation, never worse."

---

## Part 3: Random Cut Benchmark (Chain)

### Methodology

To show that speedup depends on **where** the change occurs:

1. Generate a chain of N nodes
2. Randomly select a position k (0 to N-1)
3. Remove the vulnerability at node_k (cutting the chain)
4. Measure incremental update time
5. Restore the vulnerability
6. Repeat 100 times and compute statistics

### Results

| Nodes | Iterations | Initial (ms) | Avg Incr (µs) | Min (µs) | Max (µs) | Speedup |
|------:|-----------:|-------------:|--------------:|---------:|---------:|--------:|
| 50    | 100        | 2.13         | 905.21        | 46.38    | 1877.00  | 2.3x    |
| 100   | 100        | 3.52         | 1706.50       | 110.21   | 3798.92  | 2.1x    |
| 200   | 100        | 6.83         | 3468.08       | 181.67   | 7062.46  | 2.0x    |
| 500   | 100        | 17.70        | 9289.02       | 65.12    | 19171.46 | 1.9x    |

### Key Observations

1. **Minimum time (~50-180µs)**: When cutting near the start (node_0), very few nodes need recomputation
2. **Maximum time (~1.8-19ms)**: When cutting near the end, almost all nodes are affected
3. **Average speedup ~2x**: On average, cutting at random position k affects (N-k) nodes, which averages to N/2
4. **The ratio Max/Min grows with N**: Shows the position-dependent nature of incremental updates

### Interpretation for Paper

> "The random cut benchmark demonstrates that incremental update complexity is O(affected nodes), not O(total nodes). Cutting a chain at position k only recomputes the (N-k) downstream nodes. On average, this yields a 2x speedup over full recomputation."

---

## Theoretical Analysis

### Complexity Comparison

| Operation | Full Recomputation | Incremental (Differential) |
|-----------|-------------------|---------------------------|
| Initial build | O(E × D) | O(E × D) |
| Single change | O(E × D) | O(ΔE × Δd) |

Where:
- E = number of edges in network
- D = iteration depth (diameter of attack graph)
- ΔE = edges affected by change
- Δd = local iteration depth of affected region

### When Incremental Wins

1. **Localized changes**: Patching one vulnerability in a large network
2. **Shallow topologies**: Star, tree, mesh with low diameter
3. **Frequent small updates**: Real-time monitoring scenarios

### When Incremental Ties

1. **Global changes**: Modifying the attacker's starting position
2. **Deep chains**: Changes that propagate through entire graph
3. **Complete rebuilds**: Adding/removing many nodes at once

---

## Reproducing These Results

Run the benchmarks yourself:

```bash
# Build in release mode
cargo build --release

# Run all benchmarks
cargo run --release --example run_benchmarks
```

The benchmark code is in:
- `src/benchmarks.rs` - Benchmark implementations
- `examples/run_benchmarks.rs` - Benchmark runner

---

## Conclusion

These benchmarks demonstrate that **differential dataflow provides significant speedups for incremental attack graph updates**, especially for:

1. **Large networks** with localized changes (25x+ speedup)
2. **Real-time scenarios** where sub-millisecond updates are critical
3. **Monitoring systems** that need to react to individual vulnerability patches

The worst-case performance (chain topology, cut at end) matches full recomputation, meaning incremental computation is **never slower** than rebuilding from scratch.
