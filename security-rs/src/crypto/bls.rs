use crate::types::KeyPair;
use mcl_rust::*;
use sha2::{Digest, Sha512};

/// Convert bytes to a continuous hex string (no spaces, lowercase)
fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
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

/// Initialize the BLS library with BLS12-381 curve
/// Must be called before any cryptographic operations
pub fn init_bls() {
    // Initialize mcl for BLS12-381 curve
    let success = init(CurveType::BLS12_381);
    if !success {
        panic!("Failed to initialize BLS library");
    }
}

/// Generate a BLS key pair and return as hex-encoded strings
///
/// This uses CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
/// to generate a random secret key, then derives the public key from it.
///
/// In BLS:
/// - Secret key is a random element from the Fr field (scalar field)
/// - Public key = secret_key × G2 (generator of G2 group)
pub fn generate_keypair_hex() -> KeyPair {
    let mut secret_key = Fr::zero();
    secret_key.set_by_csprng();

    // Derive public key from secret key using G2 base point multiplication
    // This is equivalent to: publicKey = secretKey.getPublicKey() in the JS version
    // Using the standard BLS12-381 G2 generator (same as mcl-wasm)
    let mut public_key = unsafe { G2::uninit() };
    let g2_generator = {
        let mut generator = unsafe { G2::uninit() };
        // Backend's actual G2 generator (derived from secret key = 1)
        // This MUST match the backend's bls-helper.ts implementation
        // Serialized format: 96 bytes (192 hex chars)
        let gen_hex = "50deedf77bb62144e12068a072d5dc7d6b7297042b51756c2bcc741c54caee8bbaeae0e28587beb2f45b62eafb6ad2035ecc66b4fcae0e430d831272aa542df21431ec26e411c687f5c5541c87fb2d6d23cf31ca3056cd4c98ceaa91cb48cb0d";
        let gen_bytes = hex_to_bytes(gen_hex).expect("Failed to decode G2 generator hex");
        if !generator.deserialize(&gen_bytes) {
            panic!("Failed to deserialize G2 generator");
        }
        generator
    };
    G2::mul(&mut public_key, &g2_generator, &secret_key);

    KeyPair {
        secret_key: bytes_to_hex(&secret_key.serialize()),
        public_key: bytes_to_hex(&public_key.serialize()),
    }
}

/// Generate a random ID as a hex string
///
/// In BLS, an ID is just a random element from the Fr field (scalar field)
/// used for threshold cryptography and identification
pub fn generate_id_hex() -> String {
    let mut id = Fr::zero();
    id.set_by_csprng();
    bytes_to_hex(&id.serialize())
}

/// Compute pairing e(P, Q) where P is in G1 and Q is in G2
pub fn pairing(p: &G1, q: &G2) -> GT {
    let mut result = unsafe { GT::uninit() };
    unsafe {
        super::ffi::mclBn_pairing(&mut result, p, q);
    }
    result
}

/// Hash data to G1 curve point
pub fn hash_to_g1(data: &[u8]) -> Result<G1, String> {
    let mut result = unsafe { G1::uninit() };
    let ret = unsafe { super::ffi::mclBnG1_hashAndMapTo(&mut result, data.as_ptr(), data.len()) };

    if ret != 0 {
        Err("Failed to hash to G1".to_string())
    } else {
        Ok(result)
    }
}

/// Hash data to Fr field element
pub fn hash_to_fr(data: &[u8]) -> Result<Fr, String> {
    let mut result = unsafe { Fr::uninit() };
    let ret = unsafe { super::ffi::mclBnFr_setHashOf(&mut result, data.as_ptr(), data.len()) };

    if ret != 0 {
        Err("Failed to hash to Fr".to_string())
    } else {
        Ok(result)
    }
}

/// Sign data using BLS signature
///
/// This follows the same process as the TypeScript Hiver.sign():
/// 1. Compute SHA-512 hash of the data
/// 2. Sign the hash using the secret key
/// 3. Return signature as hex string
///
/// # Arguments
/// * `data` - The data to sign (as UTF-8 bytes)
/// * `secret_key_hex` - The secret key in hex format
///
/// # Returns
/// The signature as a hex string
pub fn sign(data: &[u8], secret_key_hex: &str) -> Result<String, String> {
    // Parse secret key from hex
    let sk_bytes = hex_to_bytes(secret_key_hex)?;
    let mut secret_key = Fr::zero();
    if !secret_key.deserialize(&sk_bytes) {
        return Err("Failed to deserialize secret key".to_string());
    }

    // Hash the data with SHA-512
    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash = hasher.finalize();

    println!("DEBUG: SHA-512 hash: {}", bytes_to_hex(&hash));
    println!("DEBUG: SHA-512 hash length: {} bytes", hash.len());

    // Hash the hash to G1 point for signing
    let message_point = hash_to_g1(&hash)?;
    println!("DEBUG: Message point (G1): {}", message_point.get_str(16));

    // Sign: signature = secret_key * message_point
    let mut signature = unsafe { G1::uninit() };
    G1::mul(&mut signature, &message_point, &secret_key);

    // Serialize to bytes using standard serialization
    let sig_bytes = signature.serialize();

    println!("DEBUG: Signature bytes length: {}", sig_bytes.len());
    println!("DEBUG: Signature hex: {}", bytes_to_hex(&sig_bytes));

    // Convert to hex string
    Ok(bytes_to_hex(&sig_bytes))
}

/// Sign data directly without SHA-512 pre-hashing
/// This matches the backend's verify() method which expects the raw message
pub fn sign_direct(data: &[u8], secret_key_hex: &str) -> Result<String, String> {
    // Parse secret key from hex
    let sk_bytes = hex_to_bytes(secret_key_hex)?;
    let mut secret_key = Fr::zero();
    if !secret_key.deserialize(&sk_bytes) {
        return Err("Failed to deserialize secret key".to_string());
    }

    println!("DEBUG: Signing data directly (no SHA-512 pre-hash)");
    println!("DEBUG: Data length: {} bytes", data.len());

    // Hash data directly to G1 point (mcl will handle hashing internally)
    let message_point = hash_to_g1(data)?;
    println!("DEBUG: Message point (G1): {}", message_point.get_str(16));

    // Sign: signature = secret_key * message_point
    let mut signature = unsafe { G1::uninit() };
    G1::mul(&mut signature, &message_point, &secret_key);

    // Serialize to bytes
    let sig_bytes = signature.serialize();

    println!("DEBUG: Signature bytes length: {}", sig_bytes.len());
    println!("DEBUG: Signature hex: {}", bytes_to_hex(&sig_bytes));

    Ok(bytes_to_hex(&sig_bytes))
}
