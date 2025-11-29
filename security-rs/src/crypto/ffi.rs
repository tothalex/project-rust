use mcl_rust::*;

// ============================================================================
// FFI Bindings for Secret Sharing (Polynomial Evaluation & Lagrange Interpolation)
// ============================================================================

// External C functions from the mcl library for secret sharing
// These are not exposed in mcl_rust but are available in the underlying C library
#[link(name = "mcl", kind = "static")]
unsafe extern "C" {
    /// Evaluate polynomial for Fr (scalar field)
    /// out = cVec[0] + cVec[1]*x + cVec[2]*x^2 + ...
    pub fn mclBn_FrEvaluatePolynomial(
        out: *mut Fr,
        c_vec: *const Fr,
        c_size: usize,
        x: *const Fr,
    ) -> i32;

    /// Lagrange interpolation for Fr
    /// Recovers the secret from shares using Lagrange interpolation
    pub fn mclBn_FrLagrangeInterpolation(
        out: *mut Fr,
        x_vec: *const Fr,
        y_vec: *const Fr,
        k: usize,
    ) -> i32;

    /// Evaluate polynomial for G1
    pub fn mclBn_G1EvaluatePolynomial(
        out: *mut G1,
        c_vec: *const G1,
        c_size: usize,
        x: *const Fr,
    ) -> i32;

    /// Lagrange interpolation for G1
    pub fn mclBn_G1LagrangeInterpolation(
        out: *mut G1,
        x_vec: *const Fr,
        y_vec: *const G1,
        k: usize,
    ) -> i32;

    /// Evaluate polynomial for G2
    pub fn mclBn_G2EvaluatePolynomial(
        out: *mut G2,
        c_vec: *const G2,
        c_size: usize,
        x: *const Fr,
    ) -> i32;

    /// Lagrange interpolation for G2
    pub fn mclBn_G2LagrangeInterpolation(
        out: *mut G2,
        x_vec: *const Fr,
        y_vec: *const G2,
        k: usize,
    ) -> i32;

    /// Pairing operation: e(P, Q)
    pub fn mclBn_pairing(z: *mut GT, x: *const G1, y: *const G2);

    /// Miller loop (first part of pairing)
    pub fn mclBn_millerLoop(z: *mut GT, x: *const G1, y: *const G2);

    /// Final exponentiation (second part of pairing)
    pub fn mclBn_finalExp(y: *mut GT, x: *const GT);

    /// Hash and map to G1
    pub fn mclBnG1_hashAndMapTo(x: *mut G1, buf: *const u8, buf_size: usize) -> i32;

    /// Set Fr from hash of buffer
    pub fn mclBnFr_setHashOf(x: *mut Fr, buf: *const u8, buf_size: usize) -> i32;
}
