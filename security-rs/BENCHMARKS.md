# Performance Benchmarks

This document explains how to run performance benchmarks for the security library.

## Quick Start

### Run Criterion Benchmarks (Recommended)

Criterion provides detailed statistics, timing information, and HTML reports:

```bash
cargo bench
```

The results will be saved in `target/criterion/` with HTML reports you can open in a browser.

### Run Memory Benchmark

To see memory usage along with timing:

```bash
cargo bench --bench memory_benchmark
```

## What Gets Benchmarked

### 1. `generate_device_storage`
- Measures time to generate a complete device storage with keypairs
- Iterations: 1,000 times
- Reports: average time, ops/sec, memory usage

### 2. `generate_contribution`
- Benchmarked with different numbers of members: 2, 3, 5, 10
- Uses majority threshold (n+1)/2
- Measures: time per operation, memory usage
- Iterations: 100 times per configuration

### 3. `generate_keypair_hex`
- Benchmarks keypair generation
- Iterations: 10,000 times
- Useful for understanding base cryptographic operation cost

### 4. `generate_id_hex`
- Benchmarks ID generation
- Iterations: 10,000 times

## Understanding Criterion Output

Criterion will show you:
- **Time**: Mean execution time with confidence intervals
- **Throughput**: Operations per second
- **Change**: Performance compared to previous runs (if available)
- **Outliers**: Statistical analysis of outlier measurements

Example output:
```
generate_device_storage  time:   [2.1234 ms 2.1456 ms 2.1678 ms]
                         change: [-1.2345% +0.1234% +1.3456%] (p = 0.45 > 0.05)
```

## Viewing HTML Reports

After running `cargo bench`, open the HTML report:

```bash
# On macOS
open target/criterion/report/index.html

# On Linux
xdg-open target/criterion/report/index.html

# On Windows
start target/criterion/report/index.html
```

## Advanced Memory Profiling

For detailed memory profiling, you can use:

### Using Valgrind (Linux/macOS)

```bash
# Install valgrind first
# macOS: brew install valgrind
# Linux: sudo apt-get install valgrind

# Run with massif (heap profiler)
valgrind --tool=massif --massif-out-file=massif.out \
  cargo bench --bench memory_benchmark --no-run

# Visualize the results
ms_print massif.out
```

### Using Heaptrack (Linux)

```bash
# Install heaptrack
# sudo apt-get install heaptrack

# Run benchmark under heaptrack
heaptrack cargo bench --bench memory_benchmark
```

### Using Instruments (macOS)

```bash
# Build the benchmark in release mode
cargo build --release --bench memory_benchmark

# Run with Instruments
instruments -t "Allocations" \
  ./target/release/deps/memory_benchmark-*
```

## CPU Profiling

### Using perf (Linux)

```bash
# Record performance data
perf record --call-graph dwarf \
  cargo bench --bench crypto_benchmarks

# View the report
perf report
```

### Using Instruments (macOS)

```bash
# Build release binary
cargo build --release --bench crypto_benchmarks

# Profile with Time Profiler
instruments -t "Time Profiler" \
  ./target/release/deps/crypto_benchmarks-*
```

### Using cargo-flamegraph

```bash
# Install flamegraph
cargo install flamegraph

# Generate flamegraph (Linux only, requires perf)
cargo flamegraph --bench crypto_benchmarks
```

## Comparing Performance Changes

Criterion automatically saves baseline results. To compare against a saved baseline:

```bash
# Save current performance as baseline
cargo bench -- --save-baseline my-baseline

# Make your changes...

# Compare against baseline
cargo bench -- --baseline my-baseline
```

## Tips for Accurate Benchmarks

1. **Close other applications** to reduce system noise
2. **Run in release mode** (benchmarks do this automatically)
3. **Run multiple times** to ensure consistency
4. **Disable CPU frequency scaling** on Linux:
   ```bash
   echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
   ```
5. **Plug in laptop** to avoid power-saving throttling

## Interpreting Results

### Time Metrics
- **Mean**: Average execution time
- **Median**: Middle value (less affected by outliers)
- **Std Dev**: Variability in measurements

### Memory Metrics
- **RSS**: Resident Set Size (actual RAM used)
- **Peak**: Maximum memory used during execution

### Throughput
- Operations per second (higher is better)
- Useful for comparing different implementations

## Example Benchmark Session

```bash
# Run all benchmarks
cargo bench

# Run only device storage benchmark
cargo bench generate_device_storage

# Run only contribution benchmarks
cargo bench generate_contribution

# Run memory benchmark with output
cargo bench --bench memory_benchmark

# Save baseline before making changes
cargo bench -- --save-baseline before-optimization

# After making changes, compare
cargo bench -- --baseline before-optimization
```
