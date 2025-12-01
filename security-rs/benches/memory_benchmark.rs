/// This is a manual benchmark to measure memory usage
/// Run with: cargo run --release --bin memory_benchmark
use security::{generate_contribution, generate_device_storage, generate_id_hex, generate_keypair_hex, init_bls, Member};
use std::time::Instant;

fn print_memory_info() {
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        let output = Command::new("ps")
            .args(&["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .expect("Failed to execute ps");

        if let Ok(mem_str) = String::from_utf8(output.stdout) {
            if let Ok(mem_kb) = mem_str.trim().parse::<f64>() {
                println!("Current memory usage: {:.2} MB", mem_kb / 1024.0);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("VmRSS:") {
                    println!("Memory usage: {}", line);
                }
            }
        }
    }
}

fn main() {
    println!("=== Security Library Performance Benchmarks ===\n");

    init_bls();
    println!("BLS initialized\n");

    // Benchmark generate_device_storage
    println!("--- Benchmarking generate_device_storage ---");
    print_memory_info();

    let iterations = 1000;
    let start = Instant::now();

    for i in 0..iterations {
        let _ = generate_device_storage(&format!("Device {}", i));
    }

    let duration = start.elapsed();
    print_memory_info();

    println!("Total time for {} iterations: {:?}", iterations, duration);
    println!("Average time per call: {:?}", duration / iterations);
    println!("Operations per second: {:.2}\n", iterations as f64 / duration.as_secs_f64());

    // Benchmark generate_contribution with different member counts
    for num_members in [2, 3, 5, 10] {
        println!("--- Benchmarking generate_contribution with {} members ---", num_members);
        print_memory_info();

        let members: Vec<Member> = (0..num_members)
            .map(|_| Member {
                id: generate_id_hex(),
                pm: generate_keypair_hex().public_key,
            })
            .collect();

        let threshold = (num_members + 1) / 2;
        let iterations = 100;

        let start = Instant::now();

        for _ in 0..iterations {
            let _ = generate_contribution(threshold, &members);
        }

        let duration = start.elapsed();
        print_memory_info();

        println!("Threshold: {}/{}", threshold, num_members);
        println!("Total time for {} iterations: {:?}", iterations, duration);
        println!("Average time per call: {:?}", duration / iterations);
        println!("Operations per second: {:.2}\n", iterations as f64 / duration.as_secs_f64());
    }

    // Benchmark keypair generation
    println!("--- Benchmarking generate_keypair_hex ---");
    print_memory_info();

    let iterations = 10000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = generate_keypair_hex();
    }

    let duration = start.elapsed();
    print_memory_info();

    println!("Total time for {} iterations: {:?}", iterations, duration);
    println!("Average time per call: {:?}", duration / iterations);
    println!("Operations per second: {:.2}\n", iterations as f64 / duration.as_secs_f64());

    // Benchmark ID generation
    println!("--- Benchmarking generate_id_hex ---");
    print_memory_info();

    let iterations = 10000;
    let start = Instant::now();

    for _ in 0..iterations {
        let _ = generate_id_hex();
    }

    let duration = start.elapsed();
    print_memory_info();

    println!("Total time for {} iterations: {:?}", iterations, duration);
    println!("Average time per call: {:?}", duration / iterations);
    println!("Operations per second: {:.2}", iterations as f64 / duration.as_secs_f64());
}
