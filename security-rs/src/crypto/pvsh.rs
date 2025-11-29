use mcl_rust::*;
use super::bls::{pairing, hash_to_g1, hash_to_fr};

/// PVSH Encode for G2 (encrypt a secret share)
///
/// Encrypts a secret share `sh` so that only the holder of the secret key
/// corresponding to `pk` can decrypt it, while allowing public verification.
///
/// # Arguments
/// * `receiver_id` - ID of the receiver
/// * `receiver_pk` - Public key of the receiver (G2)
/// * `sh` - Secret share to encrypt (Fr)
/// * `helper_g2` - Helper generator in G2
///
/// # Returns
/// Encrypted share as string in format "c.U.V" where:
/// - c: challenge (Fr)
/// - U: commitment (G2)
/// - V: proof (G1)
pub fn pvsh_encode_g2(
    receiver_id: &Fr,
    receiver_pk: &G2,
    sh: &Fr,
    helper_g2: &G2,
) -> Result<String, String> {
    // Algorithm 1: Generate random r
    let mut r = Fr::zero();
    r.set_by_csprng();

    // Algorithm 2: Q = HashAndMapToG1(ID || PK)
    let mut id_pk_bytes = receiver_id.serialize();
    id_pk_bytes.extend_from_slice(&receiver_pk.serialize());
    let q = hash_to_g1(&id_pk_bytes)?;

    // Algorithm 3: e = pairing(Q, PK * r), then eh = hash(e)
    let mut pk_r = unsafe { G2::uninit() };
    G2::mul(&mut pk_r, receiver_pk, &r);
    let e = pairing(&q, &pk_r);
    let eh = hash_to_fr(&e.serialize())?;

    // Algorithm 4: c = sh + eh
    let mut c = unsafe { Fr::uninit() };
    Fr::add(&mut c, sh, &eh);

    // Algorithm 5: U = helper_g2 * r
    let mut u = unsafe { G2::uninit() };
    G2::mul(&mut u, helper_g2, &r);

    // Algorithm 6: H = HashAndMapToG1(Q || c || U)
    let mut q_c_u_bytes = q.serialize();
    q_c_u_bytes.extend_from_slice(&c.serialize());
    q_c_u_bytes.extend_from_slice(&u.serialize());
    let h = hash_to_g1(&q_c_u_bytes)?;

    // Algorithm 7: V = H * (eh / r)
    let mut eh_div_r = unsafe { Fr::uninit() };
    Fr::div(&mut eh_div_r, &eh, &r);
    let mut v = unsafe { G1::uninit() };
    G1::mul(&mut v, &h, &eh_div_r);

    // Algorithm 8: Return "c.U.V"
    Ok(format!(
        "{}.{}.{}",
        c.get_str(16),
        u.get_str(16),
        v.get_str(16)
    ))
}

/// PVSH Verify for G2 (verify an encrypted share)
///
/// Verifies that an encrypted share is valid without decrypting it.
///
/// # Arguments
/// * `receiver_id` - ID of the receiver
/// * `receiver_pk` - Public key of the receiver (G2)
/// * `receiver_ph` - Expected public share for the receiver (G2)
/// * `esh` - Encrypted share string "c.U.V"
/// * `helper_g2` - Helper generator in G2
///
/// # Returns
/// Ok(()) if valid, Err with reason if invalid
pub fn pvsh_verify_g2(
    receiver_id: &Fr,
    receiver_pk: &G2,
    receiver_ph: &G2,
    esh: &str,
    helper_g2: &G2,
) -> Result<(), String> {
    // Parse ESH
    let parts: Vec<&str> = esh.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid ESH format".to_string());
    }

    let mut c = Fr::zero();
    if !c.set_str(parts[0], 16) {
        return Err("Failed to parse c".to_string());
    }

    let mut u = unsafe { G2::uninit() };
    if !u.set_str(parts[1], 16) {
        return Err("Failed to parse U".to_string());
    }

    let mut v = unsafe { G1::uninit() };
    if !v.set_str(parts[2], 16) {
        return Err("Failed to parse V".to_string());
    }

    // Algorithm 1: Q = HashAndMapToG1(ID || PK)
    let mut id_pk_bytes = receiver_id.serialize();
    id_pk_bytes.extend_from_slice(&receiver_pk.serialize());
    let q = hash_to_g1(&id_pk_bytes)?;

    // Algorithm 2: H = HashAndMapToG1(Q || c || U)
    let mut q_c_u_bytes = q.serialize();
    q_c_u_bytes.extend_from_slice(&c.serialize());
    q_c_u_bytes.extend_from_slice(&u.serialize());
    let h = hash_to_g1(&q_c_u_bytes)?;

    // Algorithm 3: e1 = pairing(H, helper_g2 * c)
    let mut helper_c = unsafe { G2::uninit() };
    G2::mul(&mut helper_c, helper_g2, &c);
    let e1 = pairing(&h, &helper_c);

    // Algorithm 3: e2 = pairing(H, PH) * pairing(V, U)
    let e2_part1 = pairing(&h, receiver_ph);
    let e2_part2 = pairing(&v, &u);
    let mut e2 = unsafe { GT::uninit() };
    GT::mul(&mut e2, &e2_part1, &e2_part2);

    // Algorithm 4: Check e1 == e2
    if e1 != e2 {
        return Err("MISMATCH_PH_AND_CIPHER_TEXT".to_string());
    }

    Ok(())
}

/// PVSH Decode for G2 (decrypt an encrypted share)
///
/// Decrypts an encrypted share using the receiver's secret key.
///
/// # Arguments
/// * `receiver_id` - ID of the receiver
/// * `receiver_pk` - Public key of the receiver (G2)
/// * `receiver_sk` - Secret key of the receiver (Fr)
/// * `esh` - Encrypted share string "c.U.V"
///
/// # Returns
/// The decrypted secret share (Fr)
pub fn pvsh_decode_g2(
    receiver_id: &Fr,
    receiver_pk: &G2,
    receiver_sk: &Fr,
    esh: &str,
) -> Result<Fr, String> {
    // Parse ESH
    let parts: Vec<&str> = esh.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid ESH format".to_string());
    }

    let mut c = Fr::zero();
    if !c.set_str(parts[0], 16) {
        return Err("Failed to parse c".to_string());
    }

    let mut u = unsafe { G2::uninit() };
    if !u.set_str(parts[1], 16) {
        return Err("Failed to parse U".to_string());
    }

    // Algorithm 1: Q = HashAndMapToG1(ID || PK)
    let mut id_pk_bytes = receiver_id.serialize();
    id_pk_bytes.extend_from_slice(&receiver_pk.serialize());
    let q = hash_to_g1(&id_pk_bytes)?;

    // Algorithm 2: e = pairing(Q * SK, U), then eh = hash(e)
    let mut q_sk = unsafe { G1::uninit() };
    G1::mul(&mut q_sk, &q, receiver_sk);
    let e = pairing(&q_sk, &u);
    let eh = hash_to_fr(&e.serialize())?;

    // Algorithm 3: sh = c - eh
    let mut sh = unsafe { Fr::uninit() };
    Fr::sub(&mut sh, &c, &eh);

    Ok(sh)
}
