# Performance Benchmarks - TypeScript

This document explains how to run performance benchmarks for the TypeScript security library.

## Quick Start

### Run Vitest Benchmarks (Recommended)

Vitest provides detailed benchmarking capabilities:

```bash
pnpm bench
```

### Run Custom Performance Benchmarks

For detailed memory and CPU profiling:

```bash
pnpm bench:perf
```

## What Gets Benchmarked

### 1. `new VirtualDevice()`
- Measures time to create a new virtual device with storage
- Includes: 2 keypair generations, 2 ID generations
- Iterations: 1,000 times
- Reports: average time, ops/sec, memory usage

### 2. `generateContribution()`
- Benchmarked with different numbers of members: 2, 3, 5, 10
- Uses majority threshold (n+1)/2
- Measures: time per operation, memory usage
- Iterations: 100 times per configuration

### 3. `Hiver.generateKeyPairHex()`
- Benchmarks BLS keypair generation
- Iterations: 10,000 times
- Useful for understanding base cryptographic operation cost

### 4. `Hiver.generateId()`
- Benchmarks random ID generation
- Iterations: 10,000 times

## Running Benchmarks

### Using Vitest (Interactive)

```bash
# Run all benchmarks
pnpm bench

# Run only specific benchmarks
pnpm bench virtual-device

# Run with UI
pnpm bench --ui
```

### Using Custom Script (Detailed)

```bash
# Run custom performance script
pnpm bench:perf
```

This provides:
- Detailed timing information
- Memory usage (RSS, Heap)
- Operations per second
- Before/after memory comparison

## Understanding Output

### Vitest Benchmark Output

```
✓ src/lib/virtual-device.bench.ts (6)
  ✓ VirtualDevice Performance Benchmarks (2)
    name                                    hz     min     max    mean      p75      p99     p995     p999     rme  samples
  · new VirtualDevice()             1,234.56  0.8012  1.2345  0.8102   0.8201   0.9102   0.9502   1.0102  ±0.45%     1000
```

- **hz**: Operations per second (higher is better)
- **mean**: Average execution time in milliseconds
- **p99**: 99th percentile (most operations complete in this time or less)
- **rme**: Relative margin of error (lower is better)

### Custom Script Output

```
--- Benchmarking new VirtualDevice() ---
Before: RSS=45.23MB, Heap=12.34/20.45MB
After: RSS=47.89MB, Heap=14.56/22.34MB
Total time for 1000 iterations: 234.56ms
Average time per call: 0.235ms
Operations per second: 4261.36
```

## Memory Profiling

The custom script tracks:
- **RSS (Resident Set Size)**: Total memory used by the process
- **Heap Used**: Memory allocated on the JavaScript heap
- **Heap Total**: Total heap size allocated

### Using Node.js Inspector

For detailed profiling:

```bash
# Start with inspector
node --inspect src/benchmarks/performance.ts

# Then open Chrome DevTools at chrome://inspect
```

### Using clinic.js

For production-grade profiling:

```bash
# Install clinic
pnpm add -D clinic

# Run with clinic doctor (detects performance issues)
pnpm clinic doctor -- node src/benchmarks/performance.ts

# Run with clinic bubbleprof (async operations)
pnpm clinic bubbleprof -- node src/benchmarks/performance.ts

# Run with clinic flame (flamegraph)
pnpm clinic flame -- node src/benchmarks/performance.ts
```

## Comparing with Rust

To compare TypeScript vs Rust performance:

1. Run TypeScript benchmarks:
   ```bash
   pnpm bench:perf > ts-results.txt
   ```

2. Run Rust benchmarks:
   ```bash
   cd ../security-rs
   cargo bench --bench memory_benchmark > rust-results.txt
   ```

3. Compare the results manually or use the comparison script

### Expected Performance Characteristics

**TypeScript (Node.js)**:
- Faster startup time
- Higher memory usage
- JIT compilation overhead
- Good for I/O-bound operations

**Rust**:
- Slower initial compile time
- Lower memory usage
- No JIT overhead
- Excellent for CPU-bound operations
- Zero-cost abstractions

## Tips for Accurate Benchmarks

1. **Close other applications** to reduce system noise
2. **Run multiple times** to ensure consistency
3. **Warm up the JIT**: The first runs may be slower
4. **Use production mode**: Set `NODE_ENV=production`
5. **Disable CPU throttling** on laptops (plug in)
6. **Clear Node.js cache** between runs:
   ```bash
   rm -rf node_modules/.cache
   ```

## Advanced Profiling

### CPU Profiling

```bash
# Generate CPU profile
node --prof src/benchmarks/performance.ts

# Process the profile
node --prof-process isolate-*-v8.log > cpu-profile.txt
```

### Memory Profiling

```bash
# Generate heap snapshot
node --heapsnapshot-signal=SIGUSR2 src/benchmarks/performance.ts &
PID=$!
sleep 5 && kill -SIGUSR2 $PID

# Analyze with Chrome DevTools
```

### Using autocannon (HTTP Load Testing)

If you want to benchmark HTTP endpoints:

```bash
pnpm add -D autocannon

# Benchmark API endpoint
autocannon -c 100 -d 10 http://localhost:3000/api/endpoint
```

## Example Commands

```bash
# Quick benchmark
pnpm bench

# Detailed performance with memory
pnpm bench:perf

# Benchmark with profiling
node --prof src/benchmarks/performance.ts

# Benchmark specific file
pnpm bench virtual-device.bench

# Watch mode (re-run on changes)
pnpm vitest bench --watch
```

## Interpreting Results

### Good Performance Indicators
- Low RME (< 1%)
- Consistent timing across samples
- Stable memory usage
- High operations per second

### Red Flags
- High RME (> 5%)
- Large memory growth
- Inconsistent timing
- Garbage collection pauses

## CI/CD Integration

Add to your CI pipeline:

```yaml
# .github/workflows/benchmark.yml
- name: Run Benchmarks
  run: pnpm bench:perf

- name: Check Performance Regression
  run: |
    # Compare with baseline
    # Fail if performance degrades > 10%
```

## Resources

- [Vitest Benchmarking](https://vitest.dev/guide/features.html#benchmarking)
- [Node.js Performance](https://nodejs.org/en/docs/guides/simple-profiling/)
- [clinic.js](https://clinicjs.org/)
