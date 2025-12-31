#!/bin/bash
# Generate PNG images from Graphviz DOT files

echo "Generating attack graph visualizations..."

# Check if Graphviz is installed
if ! command -v dot &> /dev/null; then
    echo "Error: Graphviz (dot) is not installed."
    echo "Install with: brew install graphviz"
    exit 1
fi

# First, run the example to generate DOT files
echo "Running graphviz_export example..."
cargo run --release --example graphviz_export

# Convert to PNG
if [ -f "graph_initial.dot" ]; then
    echo "Converting graph_initial.dot to PNG..."
    dot -Tpng graph_initial.dot -o graph_initial.png
    echo "Created: graph_initial.png"
fi

if [ -f "graph_final.dot" ]; then
    echo "Converting graph_final.dot to PNG..."
    dot -Tpng graph_final.dot -o graph_final.png
    echo "Created: graph_final.png"
fi

echo ""
echo "Done! Open the PNG files to see the attack graphs:"
echo "  open graph_initial.png graph_final.png"
