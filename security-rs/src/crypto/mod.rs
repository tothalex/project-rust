// FFI bindings to the mcl C library
mod ffi;

// Basic BLS operations
pub mod bls;

// Secret sharing (polynomial evaluation & Lagrange interpolation)
pub mod secret_sharing;

// PVSH (Publicly Verifiable Secret Handoff)
pub mod pvsh;

// Re-export commonly used functions
pub use bls::{
    generate_id_hex, generate_keypair_hex, hash_to_fr, hash_to_g1, init_bls, pairing, sign,
    sign_direct,
};
pub use pvsh::{pvsh_decode_g2, pvsh_encode_g2, pvsh_verify_g2};
pub use secret_sharing::{
    fr_evaluate_polynomial, fr_lagrange_interpolation, g2_evaluate_polynomial,
    g2_lagrange_interpolation,
};
