# Dockerfile for Dynamic Attack Graphs
# Build and run benchmarks in a reproducible environment

FROM rust:1.75-slim-bookworm

# Install dependencies
RUN apt-get update && apt-get install -y \
    graphviz \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY examples ./examples

# Build release binary (this caches dependencies)
RUN cargo build --release

# Default command: run benchmarks
CMD ["cargo", "run", "--release", "--example", "run_benchmarks"]
