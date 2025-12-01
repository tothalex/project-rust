# Security Library - Rust & TypeScript Implementations

This repository contains high-performance implementations of BLS threshold cryptography and PVSH (Publicly Verifiable Secret Homomorphism) in both Rust and TypeScript.

## 📁 Structure

```
project-rust/
├── security-rs/          # Rust implementation
├── security-ts/          # TypeScript implementation
├── security-darts/       # Dart implementation (reference)
└── benchmark-results/    # Auto-generated comparison reports
```

## 🚀 Quick Start

### Rust
```bash
cd security-rs
cargo build --release
cargo test
```

### TypeScript
```bash
cd security-ts
pnpm install
pnpm test
```

## 📊 Performance Benchmarking

### Run Both and Compare
```bash
./compare_benchmarks.sh
```

This generates:
- Raw benchmark outputs
- **Auto-generated comparison report** (markdown)
- Terminal summary

Results: `benchmark-results/COMPARISON_YYYYMMDD_HHMMSS.md`

### Individual Benchmarks

**Rust:**
```bash
cd security-rs
cargo bench                          # Detailed Criterion benchmarks
cargo bench --bench memory_benchmark # Memory profiling
./run_benchmarks.sh                  # Interactive menu
```

**TypeScript:**
```bash
cd security-ts
pnpm bench:perf  # Detailed memory/CPU profiling
pnpm bench       # Vitest benchmarks
```

## 📈 Performance Summary

Based on benchmarks:

| Operation | Rust | TypeScript | Rust Advantage |
|-----------|------|------------|----------------|
| Device Creation | 237 µs | 1,533 µs | **6.5x faster** |
| Contribution (10 members) | 11.5 ms | 75.8 ms | **6.6x faster** |
| Keypair Gen | 112 µs | 754 µs | **6.7x faster** |
| Memory Usage | ~2.6 MB | ~139 MB | **27x less** |

**TL;DR**: Rust is 6-7x faster and uses 27x less memory.

## 📚 Documentation

- **[Benchmarking Guide](./BENCHMARKING_GUIDE.md)** - Complete guide to running benchmarks
- **[Performance Comparison](./PERFORMANCE_COMPARISON.md)** - Detailed Rust vs TypeScript analysis
- **[Rust Benchmarks](./security-rs/BENCHMARKS.md)** - Rust-specific guide
- **[TypeScript Benchmarks](./security-ts/BENCHMARKS.md)** - TypeScript-specific guide

## 🔧 What's Implemented

### Core Cryptography
- ✅ BLS12-381 keypair generation
- ✅ BLS signatures
- ✅ Threshold secret sharing (Shamir)
- ✅ PVSH encoding/decoding/verification
- ✅ Contribution generation and recovery
- ✅ Actor share calculation

### Features
- ✅ Device storage generation
- ✅ Multi-party threshold key generation
- ✅ Secret recovery from partial shares
- ✅ Public verifiability

## 🧪 Testing

Both implementations have comprehensive test suites:

**Rust:**
```bash
cd security-rs
cargo test            # Run all tests
cargo test -- --nocapture  # With output
```

**TypeScript:**
```bash
cd security-ts
pnpm test            # Run all tests
pnpm test --watch    # Watch mode
```

### Test Coverage

- ✅ Key generation and derivation
- ✅ PVSH encode/decode/verify roundtrip
- ✅ Secret sharing and recovery
- ✅ Contribution generation
- ✅ Actor share calculation
- ✅ Fixed test vectors from Dart implementation

## 🎯 When to Use Each

### Use Rust When:
- ✅ High throughput (>1000 ops/sec)
- ✅ Resource-constrained environments
- ✅ Batch crypto operations
- ✅ Low latency requirements
- ✅ Cost optimization matters

### Use TypeScript When:
- ✅ Rapid development needed
- ✅ I/O-bound workloads
- ✅ Existing Node.js infrastructure
- ✅ Moderate throughput (<100 ops/sec)
- ✅ Full-stack TypeScript project

### Hybrid Approach:
Use TypeScript for API/business logic + Rust for crypto operations (via native modules).

## 🏗️ Build Requirements

### Rust
- Rust 1.70+ (2021 edition)
- Cargo
- Build tools for MCL library (see security-rs/README)

### TypeScript
- Node.js 18+
- pnpm 8+

## 📦 Dependencies

### Rust
- `mcl` - BLS12-381 cryptography (statically linked)
- `hex` - Hex encoding/decoding
- `serde` - Serialization
- `criterion` - Benchmarking

### TypeScript
- `bls-wasm` - BLS cryptography
- `vitest` - Testing and benchmarking

## 🤝 Contributing

When making changes:

1. Run tests: `cargo test` / `pnpm test`
2. Run benchmarks: `./compare_benchmarks.sh`
3. Check performance impact in generated report

## 📄 License

[Your License Here]

## 🔗 Related

- [BLS Signatures](https://en.wikipedia.org/wiki/BLS_digital_signature)
- [Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
- [BLS12-381 Curve](https://hackmd.io/@benjaminion/bls12-381)

---

**Questions?** See the [Benchmarking Guide](./BENCHMARKING_GUIDE.md) or individual implementation READMEs.
