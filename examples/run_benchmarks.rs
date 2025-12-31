// Benchmark runner for the research paper
// Run with: cargo run --release --example run_benchmarks

use dynamic_attack_graphs::benchmarks::{
    run_chain_benchmark, run_star_benchmark, run_chain_random_cut_benchmark,
    BenchmarkResults, RandomCutBenchmarkResults,
};

fn main() {
    println!("==========================================================");
    println!("  Dynamic Attack Graphs: Scalability Benchmark");
    println!("  Measuring incremental vs full recomputation");
    println!("==========================================================");
    println!();

    // PART 1: Star network benchmarks (fast - O(1) iterations)
    // Good for demonstrating scalability with large N
    println!("PART 1: Star Network Benchmarks (O(1) iteration depth)");
    println!("--------------------------------------------------------");
    let star_sizes = vec![50, 100, 200, 500, 1000];
    
    let mut star_results = Vec::new();
    for (index, &number_of_leaves) in star_sizes.iter().enumerate() {
        println!("[{}/{}] Testing star with {} leaves...", index + 1, star_sizes.len(), number_of_leaves);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        
        let result = run_star_benchmark(number_of_leaves);
        result.print_summary();
        star_results.push(result);
    }

    // PART 2: Chain network benchmarks (slow - O(N) iterations)
    // Shows worst-case convergence but still demonstrates incremental benefit
    println!();
    println!("PART 2: Chain Network Benchmarks (O(N) iteration depth)");
    println!("--------------------------------------------------------");
    println!("Note: Chain requires O(N) iterations - keeping sizes small.");
    let chain_sizes = vec![10, 50, 100, 200];
    
    let mut chain_results = Vec::new();
    for (index, &number_of_nodes) in chain_sizes.iter().enumerate() {
        println!("[{}/{}] Testing chain with {} nodes...", index + 1, chain_sizes.len(), number_of_nodes);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        
        let result = run_chain_benchmark(number_of_nodes);
        result.print_summary();
        chain_results.push(result);
    }

    // Print final tables for paper
    println!();
    println!("==========================================================");
    println!("  RESULTS TABLES (for paper)");
    println!("==========================================================");
    println!();
    
    println!("--- Star Network (scales to large N) ---");
    print_markdown_table(&star_results);
    println!();
    
    println!("--- Chain Network (worst-case iteration depth) ---");
    print_markdown_table(&chain_results);
    println!();

    // PART 3: Random Cut benchmark
    // This shows average incremental update time across random cut positions
    println!();
    println!("PART 3: Chain Network Random Cut Benchmark");
    println!("-------------------------------------------");
    println!("For each size, we cut the chain at 100 random positions and average.");
    println!("This shows that speedup depends on WHERE you cut the chain.");
    println!();
    
    let random_cut_sizes = vec![50, 100, 200, 500];
    let iterations = 100;
    
    let mut random_cut_results = Vec::new();
    for (index, &number_of_nodes) in random_cut_sizes.iter().enumerate() {
        println!("[{}/{}] Random cut test on chain with {} nodes ({} iterations)...", 
            index + 1, random_cut_sizes.len(), number_of_nodes, iterations);
        std::io::Write::flush(&mut std::io::stdout()).ok();
        
        let result = run_chain_random_cut_benchmark(number_of_nodes, iterations);
        println!("  Initial: {:.2}ms, Avg Incr: {:.2}us (min: {:.2}us, max: {:.2}us), Speedup: {:.1}x",
            result.initial_computation_time.as_secs_f64() * 1000.0,
            result.average_incremental_time.as_secs_f64() * 1_000_000.0,
            result.min_incremental_time.as_secs_f64() * 1_000_000.0,
            result.max_incremental_time.as_secs_f64() * 1_000_000.0,
            result.average_speedup);
        random_cut_results.push(result);
    }
    
    println!();
    println!("--- Random Cut Results (Chain) ---");
    print_random_cut_markdown_table(&random_cut_results);
    println!();

    println!("--- LaTeX format (Star) ---");
    print_latex_table(&star_results);
}

fn print_latex_table(results: &[BenchmarkResults]) {
    println!("LaTeX table:");
    println!("\\begin{{tabular}}{{|r|r|r|r|}}");
    println!("\\hline");
    println!("Nodes & Initial (ms) & Incremental ($\\mu$s) & Speedup \\\\");
    println!("\\hline");
    for r in results {
        let initial_ms = r.initial_computation_time.as_secs_f64() * 1000.0;
        let incremental_us = r.incremental_update_time.as_secs_f64() * 1_000_000.0;
        println!(
            "{} & {:.2} & {:.2} & {:.1}x \\\\",
            r.number_of_nodes, initial_ms, incremental_us, r.speedup_factor
        );
    }
    println!("\\hline");
    println!("\\end{{tabular}}");
}

fn print_markdown_table(results: &[BenchmarkResults]) {
    println!("Markdown table:");
    println!("| Nodes | Initial (ms) | Incremental (us) | Speedup |");
    println!("|------:|-------------:|-----------------:|--------:|");
    for r in results {
        let initial_ms = r.initial_computation_time.as_secs_f64() * 1000.0;
        let incremental_us = r.incremental_update_time.as_secs_f64() * 1_000_000.0;
        println!(
            "| {} | {:.2} | {:.2} | {:.1}x |",
            r.number_of_nodes, initial_ms, incremental_us, r.speedup_factor
        );
    }
}

fn print_random_cut_markdown_table(results: &[RandomCutBenchmarkResults]) {
    println!("| Nodes | Iterations | Initial (ms) | Avg Incr (us) | Min (us) | Max (us) | Speedup |");
    println!("|------:|-----------:|-------------:|--------------:|---------:|---------:|--------:|");
    for r in results {
        let initial_ms = r.initial_computation_time.as_secs_f64() * 1000.0;
        let avg_us = r.average_incremental_time.as_secs_f64() * 1_000_000.0;
        let min_us = r.min_incremental_time.as_secs_f64() * 1_000_000.0;
        let max_us = r.max_incremental_time.as_secs_f64() * 1_000_000.0;
        println!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.1}x |",
            r.number_of_nodes, r.number_of_iterations, initial_ms, avg_us, min_us, max_us, r.average_speedup
        );
    }
}
