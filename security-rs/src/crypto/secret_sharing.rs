use mcl_rust::*;

/// Evaluate a polynomial with Fr coefficients at point x
///
/// Given coefficients [a0, a1, a2, ...], computes:
/// result = a0 + a1*x + a2*x^2 + a3*x^3 + ...
///
/// This is used in Shamir's secret sharing to generate shares
pub fn fr_evaluate_polynomial(coefficients: &[Fr], x: &Fr) -> Result<Fr, String> {
    if coefficients.is_empty() {
        return Err("Coefficients vector cannot be empty".to_string());
    }

    let mut result = unsafe { Fr::uninit() };
    let ret = unsafe {
        super::ffi::mclBn_FrEvaluatePolynomial(
            &mut result,
            coefficients.as_ptr(),
            coefficients.len(),
            x,
        )
    };

    if ret != 0 {
        Err("Failed to evaluate polynomial".to_string())
    } else {
        Ok(result)
    }
}

/// Recover a secret using Lagrange interpolation on Fr values
///
/// Given k points (x_vec[i], y_vec[i]), recovers the value at x=0
/// This is used in threshold cryptography to reconstruct secrets
pub fn fr_lagrange_interpolation(x_vec: &[Fr], y_vec: &[Fr]) -> Result<Fr, String> {
    if x_vec.len() != y_vec.len() {
        return Err("x_vec and y_vec must have same length".to_string());
    }
    if x_vec.is_empty() {
        return Err("Input vectors cannot be empty".to_string());
    }

    let mut result = unsafe { Fr::uninit() };
    let ret = unsafe {
        super::ffi::mclBn_FrLagrangeInterpolation(
            &mut result,
            x_vec.as_ptr(),
            y_vec.as_ptr(),
            x_vec.len(),
        )
    };

    if ret != 0 {
        Err("Failed to perform Lagrange interpolation".to_string())
    } else {
        Ok(result)
    }
}

/// Evaluate a polynomial with G2 coefficients at point x
pub fn g2_evaluate_polynomial(coefficients: &[G2], x: &Fr) -> Result<G2, String> {
    if coefficients.is_empty() {
        return Err("Coefficients vector cannot be empty".to_string());
    }

    let mut result = unsafe { G2::uninit() };
    let ret = unsafe {
        super::ffi::mclBn_G2EvaluatePolynomial(
            &mut result,
            coefficients.as_ptr(),
            coefficients.len(),
            x,
        )
    };

    if ret != 0 {
        Err("Failed to evaluate polynomial".to_string())
    } else {
        Ok(result)
    }
}

/// Recover a secret using Lagrange interpolation on G2 values
pub fn g2_lagrange_interpolation(x_vec: &[Fr], y_vec: &[G2]) -> Result<G2, String> {
    if x_vec.len() != y_vec.len() {
        return Err("x_vec and y_vec must have same length".to_string());
    }
    if x_vec.is_empty() {
        return Err("Input vectors cannot be empty".to_string());
    }

    let mut result = unsafe { G2::uninit() };
    let ret = unsafe {
        super::ffi::mclBn_G2LagrangeInterpolation(
            &mut result,
            x_vec.as_ptr(),
            y_vec.as_ptr(),
            x_vec.len(),
        )
    };

    if ret != 0 {
        Err("Failed to perform Lagrange interpolation".to_string())
    } else {
        Ok(result)
    }
}
