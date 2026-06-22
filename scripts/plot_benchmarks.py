#!/usr/bin/env python3
"""Generate benchmark plots from the CSV artifact.

The script intentionally uses only the Python standard library plus matplotlib
so that the artifact pipeline remains easy to reproduce on a clean machine.
"""

from __future__ import annotations

import argparse
import csv
import shutil
from pathlib import Path

try:
    import matplotlib.pyplot as plt
except ImportError as exc:  # pragma: no cover - exercised only on missing deps.
    raise SystemExit("matplotlib is required. Install it with: pip install matplotlib") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plot DynamicAttackGraphs benchmarks.")
    parser.add_argument("--csv", default="docs/assets/benchmark_results.csv", type=Path)
    parser.add_argument("--out", default="docs/assets", type=Path)
    parser.add_argument("--paper-out", default="paper/figures", type=Path)
    parser.add_argument("--website-out", default=None, type=Path)
    return parser.parse_args()


def read_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def as_float(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    return float(value) if value else 0.0


def as_int(row: dict[str, str], key: str) -> int:
    value = row.get(key, "")
    return int(value) if value else 0


def save_and_copy(fig: plt.Figure, out_path: Path, extra_outputs: list[Path]) -> None:
    fig.tight_layout()
    fig.savefig(out_path, dpi=180)
    plt.close(fig)
    for output_dir in extra_outputs:
        output_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(out_path, output_dir / out_path.name)


def no_data_plot(title: str) -> plt.Figure:
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.text(0.5, 0.5, "No matching benchmark rows", ha="center", va="center")
    ax.set_title(title)
    ax.set_axis_off()
    return fig


def plot_topology_speedup(
    rows: list[dict[str, str]],
    topology: str,
    title: str,
    output_name: str,
    out_dir: Path,
    extra_outputs: list[Path],
) -> None:
    filtered = sorted(
        [row for row in rows if row.get("topology") == topology],
        key=lambda row: as_int(row, "number_of_nodes"),
    )
    if not filtered:
        fig = no_data_plot(title)
    else:
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.plot(
            [as_int(row, "number_of_nodes") for row in filtered],
            [as_float(row, "speedup") for row in filtered],
            marker="o",
            linewidth=2,
            color="#1f77b4",
        )
        ax.set_xlabel("Number of nodes")
        ax.set_ylabel("Speedup (full recomputation / incremental)")
        ax.set_title(title)
        ax.grid(True, alpha=0.3)
    save_and_copy(fig, out_dir / output_name, extra_outputs)


def plot_incremental_vs_recompute(
    rows: list[dict[str, str]], out_dir: Path, extra_outputs: list[Path]
) -> None:
    filtered = [
        row for row in rows if row.get("topology") in {"star", "chain"} and row.get("full_recomputation_ms")
    ]
    if not filtered:
        fig = no_data_plot("Incremental update vs full recomputation")
        save_and_copy(fig, out_dir / "incremental_vs_recompute.png", extra_outputs)
        return

    labels = [
        f"{row['topology']}\n{row['number_of_nodes']} nodes"
        for row in sorted(filtered, key=lambda row: (row["topology"], as_int(row, "number_of_nodes")))
    ]
    incremental_ms = [as_float(row, "incremental_update_us") / 1000.0 for row in filtered]
    recompute_ms = [as_float(row, "full_recomputation_ms") for row in filtered]

    fig, ax = plt.subplots(figsize=(10, 4.8))
    positions = list(range(len(labels)))
    width = 0.38
    ax.bar([pos - width / 2 for pos in positions], incremental_ms, width, label="Incremental update", color="#2ca02c")
    ax.bar([pos + width / 2 for pos in positions], recompute_ms, width, label="Full recomputation", color="#d62728")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=35, ha="right")
    ax.set_ylabel("Time (ms)")
    ax.set_title("Incremental update time compared with full recomputation")
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)
    save_and_copy(fig, out_dir / "incremental_vs_recompute.png", extra_outputs)


def plot_enterprise_patterns(
    rows: list[dict[str, str]], out_dir: Path, extra_outputs: list[Path]
) -> None:
    filtered = [row for row in rows if row.get("topology") == "layered_enterprise"]
    if not filtered:
        fig = no_data_plot("Layered enterprise update pattern speedups")
    else:
        fig, ax = plt.subplots(figsize=(8, 4.5))
        ax.bar(
            [row["update_type"] for row in filtered],
            [as_float(row, "speedup") for row in filtered],
            color="#9467bd",
        )
        ax.set_xlabel("Update type")
        ax.set_ylabel("Speedup (full recomputation / incremental)")
        ax.set_title("Layered enterprise update pattern speedups")
        ax.tick_params(axis="x", labelrotation=25)
        for label in ax.get_xticklabels():
            label.set_ha("right")
        ax.grid(True, axis="y", alpha=0.3)
    save_and_copy(fig, out_dir / "enterprise_update_patterns.png", extra_outputs)


def plot_affected_region(rows: list[dict[str, str]], out_dir: Path, extra_outputs: list[Path]) -> None:
    if not rows or "affected_hosts" not in rows[0] or "incremental_update_us" not in rows[0]:
        print("Skipping affected_region_vs_update_time.png: required columns are not available.")
        return

    filtered = [row for row in rows if row.get("affected_hosts")]
    if not filtered:
        print("Skipping affected_region_vs_update_time.png: no affected-host data in CSV.")
        return

    fig, ax = plt.subplots(figsize=(7, 4))
    ax.scatter(
        [as_float(row, "affected_hosts") for row in filtered],
        [as_float(row, "incremental_update_us") / 1000.0 for row in filtered],
        color="#17becf",
    )
    ax.set_xlabel("Affected hosts")
    ax.set_ylabel("Incremental update time (ms)")
    ax.set_title("Affected region size versus update time")
    ax.grid(True, alpha=0.3)
    save_and_copy(fig, out_dir / "affected_region_vs_update_time.png", extra_outputs)


def main() -> None:
    args = parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    args.paper_out.mkdir(parents=True, exist_ok=True)
    extra_outputs = [args.paper_out]
    if args.website_out:
        args.website_out.mkdir(parents=True, exist_ok=True)
        extra_outputs.append(args.website_out)

    rows = read_rows(args.csv)
    plot_topology_speedup(
        rows,
        "star",
        "Localized update speedup in star topologies",
        "star_speedup.png",
        args.out,
        extra_outputs,
    )
    plot_topology_speedup(
        rows,
        "chain",
        "Localized update speedup in chain topologies",
        "chain_speedup.png",
        args.out,
        extra_outputs,
    )
    plot_incremental_vs_recompute(rows, args.out, extra_outputs)
    plot_enterprise_patterns(rows, args.out, extra_outputs)
    plot_affected_region(rows, args.out, extra_outputs)


if __name__ == "__main__":
    main()
