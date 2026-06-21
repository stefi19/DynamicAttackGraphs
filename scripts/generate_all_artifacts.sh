#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

require_command() {
  local command_name="$1"
  local install_hint="$2"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing dependency: $command_name" >&2
    echo "Install it with: $install_hint" >&2
    exit 1
  fi
}

mkdir -p docs/assets paper/figures

require_command cargo "install Rust from https://rustup.rs"
require_command dot "brew install graphviz"
require_command python3 "install Python 3 from https://www.python.org"

python3 - <<'PY'
try:
    import matplotlib  # noqa: F401
except ImportError:
    raise SystemExit("Missing dependency: matplotlib\nInstall it with: pip install matplotlib")
PY

cargo fmt
cargo test
cargo build

cargo run --release --example graphviz_export
dot -Tpng graph_initial.dot -o docs/assets/graph_initial.png
dot -Tpng graph_final.dot -o docs/assets/graph_final.png
cp docs/assets/graph_initial.png paper/figures/graph_initial.png
cp docs/assets/graph_final.png paper/figures/graph_final.png

cargo run --release --example explain_goal
dot -Tpng explanation_goal.dot -o docs/assets/explanation_goal.png
cp docs/assets/explanation_goal.png paper/figures/explanation_goal.png

cargo run --release --example run_benchmarks -- --csv docs/assets/benchmark_results.csv

python3 scripts/plot_benchmarks.py \
  --csv docs/assets/benchmark_results.csv \
  --out docs/assets \
  --paper-out paper/figures

cd paper
if command -v latexmk >/dev/null 2>&1; then
  latexmk -pdf -interaction=nonstopmode -halt-on-error main.tex
else
  require_command pdflatex "install a LaTeX distribution, for example MacTeX on macOS"
  pdflatex -interaction=nonstopmode -halt-on-error main.tex
  if command -v bibtex >/dev/null 2>&1; then
    bibtex main || true
  else
    echo "bibtex not found; continuing without bibliography rebuild." >&2
  fi
  pdflatex -interaction=nonstopmode -halt-on-error main.tex
  pdflatex -interaction=nonstopmode -halt-on-error main.tex
fi
