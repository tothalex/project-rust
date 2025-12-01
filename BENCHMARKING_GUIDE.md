# Benchmarking Guide - Rust vs TypeScript

Complete guide to benchmarking and comparing the Rust and TypeScript security implementations.

## Quick Start

### Run Both Benchmarks and Compare

```bash
./compare_benchmarks.sh
```

This single command will:
1. Run Rust benchmarks
2. Run TypeScript benchmarks
3. Save timestamped results
4. **Generate formatted comparison README** ⭐
5. Display terminal comparison summary

Results are saved in `benchmark-results/` directory:
```
benchmark-results/
├── rust_20241201_143022.txt          # Raw Rust output
├── ts_20241201_143022.txt            # Raw TypeScript output
└── COMPARISON_20241201_143022.md     # Auto-generated report ⭐
```

---

## Individual Benchmarks

### Rust Only

```bash
cd security-rs

# Quick overview with memory profiling
cargo bench --bench memory_benchmark

# Detailed Criterion benchmarks
cargo bench

# Interactive benchmark runner
./run_benchmarks.sh

# View HTML reports
open target/criterion/report/index.html
```

### TypeScript Only

```bash
cd security-ts

# Custom performance script (recommended)
pnpm bench:perf

# Vitest benchmarks
pnpm bench

# Watch mode
pnpm bench --watch
```

---

## What Gets Measured

Both implementations benchmark the same operations:

1. **Device Storage Creation**
   - Rust: `generate_device_storage()`
   - TypeScript: `new VirtualDevice()`

2. **Contribution Generation**
   - Tested with 2, 3, 5, and 10 members
   - Rust: `generate_contribution()`
   - TypeScript: `device.generateContribution()`

3. **Keypair Generation**
   - Rust: `generate_keypair_hex()`
   - TypeScript: `Hiver.generateKeyPairHex()`

4. **ID Generation**
   - Rust: `generate_id_hex()`
   - TypeScript: `Hiver.generateId()`

---

## Performance Metrics

### Timing
- **Average execution time** per operation
- **Throughput** (operations per second)
- **Percentiles** (p50, p75, p99)

### Memory
- **RSS** (Resident Set Size) - actual RAM used
- **Heap usage** (TypeScript only)
- **Memory growth** over time

### CPU
- Implicit in timing measurements
- Lower time = better CPU efficiency

---

## Results Summary

See [PERFORMANCE_COMPARISON.md](./PERFORMANCE_COMPARISON.md) for detailed analysis.

**TL;DR:**
- Rust is **6-7x faster** for crypto operations
- Rust uses **27x less memory**
- TypeScript has faster development iteration
- Both scale linearly with workload

---

## Directory Structure

```
project-rust/
├── security-rs/              # Rust implementation
│   ├── benches/
│   │   ├── crypto_benchmarks.rs    # Criterion benchmarks
│   │   └── memory_benchmark.rs     # Memory profiling
│   ├── BENCHMARKS.md               # Rust benchmark guide
│   ├── BENCHMARK_RESULTS.md        # Rust results
│   └── run_benchmarks.sh           # Interactive runner
│
├── security-ts/              # TypeScript implementation
│   ├── src/benchmarks/
│   │   └── performance.ts          # Performance script
│   ├── src/lib/
│   │   └── virtual-device.bench.ts # Vitest benchmarks
│   └── BENCHMARKS.md               # TypeScript benchmark guide
│
├── benchmark-results/        # Timestamped results (git-ignored)
│   ├── rust_TIMESTAMP.txt
│   └── ts_TIMESTAMP.txt
│
├── compare_benchmarks.sh     # Automated comparison
├── PERFORMANCE_COMPARISON.md # Detailed comparison analysis
└── BENCHMARKING_GUIDE.md     # This file
```

---

## Interpreting Results

### Good Performance

✅ Low variance (RME < 1%)
✅ Consistent timing across runs
✅ Stable memory usage
✅ High ops/sec

### Concerning Signs

⚠️ High variance (RME > 5%)
⚠️ Growing memory usage
⚠️ Inconsistent timing
⚠️ Unexpectedly slow operations

---

## Advanced Profiling

### Rust

```bash
cd security-rs

# CPU profiling (Linux)
perf record cargo bench
perf report

# Flamegraph (Linux)
cargo flamegraph --bench crypto_benchmarks

# Valgrind (memory)
valgrind --tool=massif cargo bench
```

### TypeScript

```bash
cd security-ts

# CPU profiling
node --prof src/benchmarks/performance.ts
node --prof-process isolate-*.log

# Memory profiling
node --inspect src/benchmarks/performance.ts
# Then open chrome://inspect

# Using clinic.js
pnpm add -D clinic
pnpm clinic doctor -- tsx src/benchmarks/performance.ts
```

---

## Continuous Benchmarking

### Save Baseline

```bash
# Rust
cd security-rs
cargo bench -- --save-baseline before-optimization

# TypeScript
cd security-ts
pnpm bench:perf > baseline.txt
```

### Compare After Changes

```bash
# Rust
cargo bench -- --baseline before-optimization

# TypeScript
pnpm bench:perf > after-optimization.txt
diff baseline.txt after-optimization.txt
```

---

## CI/CD Integration

Add to your pipeline:

```yaml
# .github/workflows/benchmark.yml
name: Performance Benchmarks

on: [push, pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Rust
        uses: actions-rs/toolchain@v1

      - name: Setup Node.js
        uses: actions/setup-node@v2

      - name: Run Benchmarks
        run: ./compare_benchmarks.sh

      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: benchmark-results
          path: benchmark-results/
```

---

## Tips for Accurate Benchmarks

### Environment

1. **Close unnecessary applications**
2. **Disable CPU throttling** (plug in laptop)
3. **Run on dedicated hardware** for consistent results
4. **Avoid background tasks** during benchmarks

### Configuration

```bash
# Linux: Disable CPU frequency scaling
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Increase open file limits
ulimit -n 65536

# Set production mode (TypeScript)
export NODE_ENV=production
```

### Running

1. **Warm up** - First run may be slower (JIT compilation)
2. **Multiple runs** - Run 3-5 times, average results
3. **Statistical significance** - Use Criterion's built-in stats
4. **Consistent workload** - Same data sizes across runs

---

## Troubleshooting

### Rust Benchmarks Fail

```bash
# Clean and rebuild
cd security-rs
cargo clean
cargo bench

# Check MCL library builds correctly
./build.rs
```

### TypeScript Benchmarks Fail

```bash
# Reinstall dependencies
cd security-ts
rm -rf node_modules
pnpm install

# Clear caches
rm -rf node_modules/.cache
```

### Inconsistent Results

- System is under load (check Activity Monitor/top)
- Thermal throttling (laptop overheating)
- Background processes (indexing, backups)
- Network activity affecting I/O

---

## Comparing with Production

### Synthetic vs Real-World

**Synthetic benchmarks** (these):
- Controlled environment
- Isolated operations
- Measure raw performance

**Production monitoring**:
- Real user load
- Network latency included
- Database operations
- Concurrent users

### Next Steps

After synthetic benchmarks, measure production:

```bash
# Add application monitoring
# - New Relic
# - DataDog
# - Prometheus + Grafana

# Load testing
# - k6
# - Artillery
# - Gatling
```

---

## Questions?

- **Rust benchmarks**: See `security-rs/BENCHMARKS.md`
- **TypeScript benchmarks**: See `security-ts/BENCHMARKS.md`
- **Performance comparison**: See `PERFORMANCE_COMPARISON.md`
- **Implementation details**: See individual README files

---

## Summary Commands

```bash
# Quick comparison
./compare_benchmarks.sh

# Rust only (detailed)
cd security-rs && ./run_benchmarks.sh

# TypeScript only (detailed)
cd security-ts && pnpm bench:perf

# View previous results
ls -lh benchmark-results/
```

---

**Last Updated**: December 2024
