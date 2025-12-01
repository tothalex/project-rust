use super::ffi::*;

pub fn fr_evaluate_polynomial(coefficients: &[mclBnFr], x: &mclBnFr) -> Result<mclBnFr, String> {
    if coefficients.is_empty() {
        return Err("Coefficients vector cannot be empty".to_string());
    }

    unsafe {
        let mut result: mclBnFr = std::mem::zeroed();
        let ret = mclBn_FrEvaluatePolynomial(
            &mut result,
            coefficients.as_ptr(),
            coefficients.len(),
            x,
        );

        if ret != 0 {
            Err("Failed to evaluate polynomial".to_string())
        } else {
            Ok(result)
        }
    }
}

pub fn fr_lagrange_interpolation(x_vec: &[mclBnFr], y_vec: &[mclBnFr]) -> Result<mclBnFr, String> {
    if x_vec.len() != y_vec.len() {
        return Err("x_vec and y_vec must have same length".to_string());
    }
    if x_vec.is_empty() {
        return Err("Input vectors cannot be empty".to_string());
    }

    unsafe {
        let mut result: mclBnFr = std::mem::zeroed();
        let ret = mclBn_FrLagrangeInterpolation(
            &mut result,
            x_vec.as_ptr(),
            y_vec.as_ptr(),
            x_vec.len(),
        );

        if ret != 0 {
            Err("Failed to perform Lagrange interpolation".to_string())
        } else {
            Ok(result)
        }
    }
}
