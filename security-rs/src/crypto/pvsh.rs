use super::bls::{
    deserialize_fr, deserialize_g1, deserialize_g2, serialize_fr, serialize_g1, serialize_g2,
    serialize_gt,
};
use super::{hash_to_fr, hash_to_g1, pairing};
use super::ffi::*;
use super::utils::{bytes_to_hex, hex_to_bytes};
use std::mem;

pub fn pvsh_encode_g2(
    receiver_id: &mclBnFr,
    receiver_pk: &mclBnG2,
    sh: &mclBnFr,
    helper_g2: &mclBnG2,
) -> Result<String, String> {
    unsafe {
        let mut r: mclBnFr = mem::zeroed();
        let ret = mclBnFr_setByCSPRNG(&mut r);
        if ret != 0 {
            return Err("Failed to generate random r".to_string());
        }

        let mut id_pk_bytes = serialize_fr(receiver_id);
        id_pk_bytes.extend_from_slice(&serialize_g2(receiver_pk));
        let q = hash_to_g1(&id_pk_bytes)?;

        let mut pk_times_r: mclBnG2 = mem::zeroed();
        mclBnG2_mul(&mut pk_times_r, receiver_pk, &r);
        let e = pairing(&q, &pk_times_r);

        let e_bytes = serialize_gt(&e);
        let eh = hash_to_fr(&e_bytes)?;

        let mut c: mclBnFr = mem::zeroed();
        mclBnFr_add(&mut c, sh, &eh);

        let mut u: mclBnG2 = mem::zeroed();
        mclBnG2_mul(&mut u, helper_g2, &r);

        let mut hash_input = serialize_g1(&q);
        hash_input.extend_from_slice(&serialize_fr(&c));
        hash_input.extend_from_slice(&serialize_g2(&u));
        let h = hash_to_g1(&hash_input)?;

        let mut eh_div_r: mclBnFr = mem::zeroed();
        mclBnFr_div(&mut eh_div_r, &eh, &r);
        let mut v: mclBnG1 = mem::zeroed();
        mclBnG1_mul(&mut v, &h, &eh_div_r);

        let c_hex = bytes_to_hex(&serialize_fr(&c));
        let u_hex = bytes_to_hex(&serialize_g2(&u));
        let v_hex = bytes_to_hex(&serialize_g1(&v));

        Ok(format!("{}.{}.{}", c_hex, u_hex, v_hex))
    }
}

pub fn pvsh_verify_g2(
    receiver_id: &mclBnFr,
    receiver_pk: &mclBnG2,
    expected_public: &mclBnG2,
    esh: &str,
    helper_g2: &mclBnG2,
) -> Result<(), String> {
    unsafe {
        let parts: Vec<&str> = esh.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid ESH format".to_string());
        }

        let c_bytes = hex_to_bytes(parts[0])?;
        let u_bytes = hex_to_bytes(parts[1])?;
        let v_bytes = hex_to_bytes(parts[2])?;

        let c = deserialize_fr(&c_bytes)?;
        let u = deserialize_g2(&u_bytes)?;
        let v = deserialize_g1(&v_bytes)?;

        let mut id_pk_bytes = serialize_fr(receiver_id);
        id_pk_bytes.extend_from_slice(&serialize_g2(receiver_pk));
        let q = hash_to_g1(&id_pk_bytes)?;

        let mut hash_input = serialize_g1(&q);
        hash_input.extend_from_slice(&serialize_fr(&c));
        hash_input.extend_from_slice(&serialize_g2(&u));
        let h = hash_to_g1(&hash_input)?;

        let mut helper_times_c: mclBnG2 = mem::zeroed();
        mclBnG2_mul(&mut helper_times_c, helper_g2, &c);
        let e1 = pairing(&h, &helper_times_c);

        let pairing1 = pairing(&h, expected_public);
        let pairing2 = pairing(&v, &u);
        let mut e2: mclBnGT = mem::zeroed();
        mclBnGT_mul(&mut e2, &pairing1, &pairing2);

        if mclBnGT_isEqual(&e1, &e2) == 0 {
            return Err("MISMATCH_PH_AND_CHIPER_TEXT".to_string());
        }

        Ok(())
    }
}

pub fn pvsh_decode_g2(
    receiver_id: &mclBnFr,
    receiver_pk: &mclBnG2,
    receiver_sk: &mclBnFr,
    esh: &str,
) -> Result<mclBnFr, String> {
    unsafe {
        let parts: Vec<&str> = esh.split('.').collect();
        if parts.len() != 3 {
            return Err("Invalid ESH format".to_string());
        }

        let c_bytes = hex_to_bytes(parts[0])?;
        let u_bytes = hex_to_bytes(parts[1])?;

        let c = deserialize_fr(&c_bytes)?;
        let u = deserialize_g2(&u_bytes)?;

        let mut id_pk_bytes = serialize_fr(receiver_id);
        id_pk_bytes.extend_from_slice(&serialize_g2(receiver_pk));
        let q = hash_to_g1(&id_pk_bytes)?;

        let mut q_times_sk: mclBnG1 = mem::zeroed();
        mclBnG1_mul(&mut q_times_sk, &q, receiver_sk);
        let e = pairing(&q_times_sk, &u);

        let e_bytes = serialize_gt(&e);
        let eh = hash_to_fr(&e_bytes)?;

        let mut sh: mclBnFr = mem::zeroed();
        mclBnFr_sub(&mut sh, &c, &eh);

        Ok(sh)
    }
}
