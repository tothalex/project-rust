pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string must have even length".to_string());
    }

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let hex_str =
                std::str::from_utf8(chunk).map_err(|e| format!("Invalid UTF-8: {}", e))?;
            u8::from_str_radix(hex_str, 16).map_err(|e| format!("Invalid hex: {}", e))
        })
        .collect()
}
