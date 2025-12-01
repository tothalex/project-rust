use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bls_dir = out_dir.join("bls");

    // Clone bls library (which includes mcl as a submodule)
    if !bls_dir.exists() {
        println!("cargo:warning=Cloning bls library (includes mcl)...");
        let status = Command::new("git")
            .args(&[
                "clone",
                "--depth",
                "1",
                "--recursive",
                "https://github.com/herumi/bls.git",
                bls_dir.to_str().unwrap(),
            ])
            .status()
            .expect("Failed to clone bls repository");

        if !status.success() {
            panic!("Failed to clone bls repository");
        }
    }

    // Build bls using make (this also builds mcl as a dependency)
    println!("cargo:warning=Building bls library with BLS12-381 support...");

    let status = Command::new("make")
        .current_dir(&bls_dir)
        .env("CFLAGS", "-O3 -DNDEBUG -fPIC")
        .env("CXXFLAGS", "-O3 -DNDEBUG -fPIC")
        .args(&["-j", "lib/libbls384_256.a"])
        .status()
        .expect("Failed to build bls");

    if !status.success() {
        panic!("Failed to build bls library");
    }

    // Also build mcl library (for low-level operations)
    let mcl_dir = bls_dir.join("mcl");
    println!("cargo:warning=Building mcl library...");

    let status = Command::new("make")
        .current_dir(&mcl_dir)
        .env("CFLAGS", "-O3 -DNDEBUG -fPIC")
        .env("CXXFLAGS", "-O3 -DNDEBUG -fPIC")
        .args(&["-j", "lib/libmcl.a"])
        .status()
        .expect("Failed to build mcl");

    if !status.success() {
        panic!("Failed to build mcl library");
    }

    // Link to both libraries (order matters: bls first, then mcl)
    println!("cargo:rustc-link-search=native={}/lib", bls_dir.display());
    println!("cargo:rustc-link-search=native={}/lib", mcl_dir.display());
    println!("cargo:rustc-link-lib=static=bls384_256");
    println!("cargo:rustc-link-lib=static=mcl");

    // Also need to link C++ standard library
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // Tell cargo to rerun if the bls directory changes
    println!("cargo:rerun-if-changed={}", bls_dir.display());
}
