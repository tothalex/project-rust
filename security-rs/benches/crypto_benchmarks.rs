use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use security::{generate_device_storage, generate_contribution, generate_id_hex, generate_keypair_hex, init_bls, Member};
use std::sync::Once;

static INIT: Once = Once::new();

fn initialize() {
    INIT.call_once(|| {
        init_bls();
    });
}

fn bench_generate_device_storage(c: &mut Criterion) {
    initialize();

    c.bench_function("generate_device_storage", |b| {
        b.iter(|| {
            generate_device_storage(black_box("Test Device"))
        });
    });
}

fn bench_generate_contribution(c: &mut Criterion) {
    initialize();

    let mut group = c.benchmark_group("generate_contribution");

    // Test with different numbers of members
    for num_members in [2, 3, 5, 10].iter() {
        // Create members for the test
        let members: Vec<Member> = (0..*num_members)
            .map(|_| Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            })
            .collect();

        let threshold = (*num_members + 1) / 2; // Simple threshold: majority

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_members_t{}", num_members, threshold)),
            num_members,
            |b, _| {
                b.iter(|| {
                    generate_contribution(
                        black_box(threshold),
                        black_box(&members),
                    )
                });
            },
        );
    }

    group.finish();
}

fn bench_keypair_generation(c: &mut Criterion) {
    initialize();

    c.bench_function("generate_keypair_hex", |b| {
        b.iter(|| {
            generate_keypair_hex()
        });
    });
}

fn bench_id_generation(c: &mut Criterion) {
    initialize();

    c.bench_function("generate_id_hex", |b| {
        b.iter(|| {
            generate_id_hex()
        });
    });
}

criterion_group!(
    benches,
    bench_generate_device_storage,
    bench_generate_contribution,
    bench_keypair_generation,
    bench_id_generation
);
criterion_main!(benches);
