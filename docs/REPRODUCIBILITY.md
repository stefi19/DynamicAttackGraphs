# Reproducibility Workflow

This repository is a research prototype. Regenerate benchmark numbers and
figures on the target machine before reporting final results.

## Dependencies

- Rust stable: <https://rustup.rs>
- Graphviz: `brew install graphviz`
- Python 3
- matplotlib: `pip install matplotlib`
- LaTeX distribution with `latexmk` or `pdflatex`/`bibtex`
- Optional future baseline: Souffle

## Generate Everything

```bash
./scripts/generate_all_artifacts.sh
```

The script runs formatting, tests, build validation, Graphviz examples,
benchmark CSV export, benchmark plotting, paper compilation, and website asset
copying.

## Regenerate Benchmark CSV

```bash
cargo run --release --example run_benchmarks -- --csv docs/assets/benchmark_results.csv
```

The CSV is machine dependent. Do not report old speedup numbers without
regenerating the file.

## Regenerate Benchmark Plots

```bash
python3 scripts/plot_benchmarks.py \
  --csv docs/assets/benchmark_results.csv \
  --out docs/assets \
  --paper-out paper/figures \
  --website-out website/assets
```

The plotting script skips optional plots when required columns are not available.

## Compile the Paper

```bash
cd paper
latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
```

If `latexmk` is unavailable, use:

```bash
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main || true
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
```

The expected output is `paper/main.pdf`.

## Open the Website

```bash
open website/index.html
```

or:

```bash
python3 -m http.server 8000
open http://localhost:8000/website/
```

The website is static and requires no backend. It expects generated images and
the compiled PDF under `website/assets/`.
