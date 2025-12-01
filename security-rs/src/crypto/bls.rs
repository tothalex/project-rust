use super::ffi::*;
use crate::types::KeyPair;
use super::utils::{bytes_to_hex, hex_to_bytes};
use sha2::{Digest, Sha512};
use std::mem;

pub fn serialize_fr(fr: &mclBnFr) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; FR_SIZE];
        let size = mclBnFr_serialize(buf.as_mut_ptr() as *mut _, FR_SIZE, fr);
        buf.truncate(size);
        buf
    }
}

pub fn deserialize_fr(bytes: &[u8]) -> Result<mclBnFr, String> {
    unsafe {
        let mut fr: mclBnFr = mem::zeroed();
        let consumed = mclBnFr_deserialize(&mut fr, bytes.as_ptr() as *const _, bytes.len());
        if consumed == 0 {
            Err("Failed to deserialize Fr".to_string())
        } else {
            Ok(fr)
        }
    }
}

pub fn serialize_g1(g1: &mclBnG1) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; G1_SIZE];
        let size = mclBnG1_serialize(buf.as_mut_ptr() as *mut _, G1_SIZE, g1);
        buf.truncate(size);
        buf
    }
}

pub fn deserialize_g1(bytes: &[u8]) -> Result<mclBnG1, String> {
    unsafe {
        let mut g1: mclBnG1 = mem::zeroed();
        let consumed = mclBnG1_deserialize(&mut g1, bytes.as_ptr() as *const _, bytes.len());
        if consumed == 0 {
            Err("Failed to deserialize G1".to_string())
        } else {
            Ok(g1)
        }
    }
}

pub fn serialize_g2(g2: &mclBnG2) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; G2_SIZE];
        let size = mclBnG2_serialize(buf.as_mut_ptr() as *mut _, G2_SIZE, g2);
        buf.truncate(size);
        buf
    }
}

pub fn deserialize_g2(bytes: &[u8]) -> Result<mclBnG2, String> {
    unsafe {
        let mut g2: mclBnG2 = mem::zeroed();
        let consumed = mclBnG2_deserialize(&mut g2, bytes.as_ptr() as *const _, bytes.len());
        if consumed == 0 {
            Err("Failed to deserialize G2".to_string())
        } else {
            Ok(g2)
        }
    }
}

pub fn serialize_gt(gt: &mclBnGT) -> Vec<u8> {
    unsafe {
        let mut buf = vec![0u8; GT_SIZE];
        let size = mclBnGT_serialize(buf.as_mut_ptr() as *mut _, GT_SIZE, gt);
        buf.truncate(size);
        buf
    }
}

pub fn init_bls() {
    unsafe {
        let ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
        if ret != 0 {
            panic!("Failed to initialize BN library: error code {}", ret);
        }

        let ret = blsInit(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
        if ret != 0 {
            panic!("Failed to initialize BLS library: error code {}", ret);
        }
    }
}

pub fn generate_keypair_hex() -> KeyPair {
    unsafe {
        let mut sec_key: BlsSecretKey = mem::zeroed();
        let ret = blsSecretKeySetByCSPRNG(&mut sec_key);
        if ret != 0 {
            panic!("Failed to generate secret key: error code {}", ret);
        }

        let mut sec_buf = vec![0u8; BLS_SECRET_KEY_SIZE];
        let sec_size = blsSecretKeySerialize(
            sec_buf.as_mut_ptr() as *mut _,
            BLS_SECRET_KEY_SIZE,
            &sec_key,
        );
        if sec_size == 0 {
            panic!("Failed to serialize secret key");
        }

        let mut pub_key: BlsPublicKey = mem::zeroed();
        blsGetPublicKey(&mut pub_key, &sec_key);

        let mut pub_buf = vec![0u8; G2_SIZE];
        let pub_size = mclBnG2_serialize(pub_buf.as_mut_ptr() as *mut _, G2_SIZE, &pub_key.v);
        if pub_size == 0 {
            panic!("Failed to serialize public key");
        }

        KeyPair {
            secret_key: bytes_to_hex(&sec_buf[..sec_size]),
            public_key: bytes_to_hex(&pub_buf[..pub_size]),
        }
    }
}

pub fn generate_id_hex() -> String {
    unsafe {
        let mut fr: mclBnFr = mem::zeroed();
        let ret = mclBnFr_setByCSPRNG(&mut fr);
        if ret != 0 {
            panic!("Failed to generate random ID: error code {}", ret);
        }

        let mut buf = vec![0u8; FR_SIZE];
        let size = mclBnFr_serialize(buf.as_mut_ptr() as *mut _, FR_SIZE, &fr);
        if size == 0 {
            panic!("Failed to serialize ID");
        }

        bytes_to_hex(&buf[..size])
    }
}

pub fn derive_public_key_g2(secret_key_fr: &mclBnFr) -> mclBnG2 {
    unsafe {
        let mut sec_buf = vec![0u8; FR_SIZE];
        let size = mclBnFr_serialize(sec_buf.as_mut_ptr() as *mut _, FR_SIZE, secret_key_fr);
        if size == 0 {
            panic!("Failed to serialize Fr for public key derivation");
        }

        let mut bls_sec: BlsSecretKey = mem::zeroed();
        let consumed = blsSecretKeyDeserialize(&mut bls_sec, sec_buf.as_ptr() as *const _, size);
        if consumed == 0 {
            panic!("Failed to deserialize secret key");
        }

        let mut bls_pub: BlsPublicKey = mem::zeroed();
        blsGetPublicKey(&mut bls_pub, &bls_sec);

        bls_pub.v
    }
}

pub fn get_g2_generator() -> mclBnG2 {
    unsafe {
        let mut one: mclBnFr = mem::zeroed();
        mclBnFr_setInt(&mut one, 1);
        derive_public_key_g2(&one)
    }
}

pub fn hash_to_g1(data: &[u8]) -> Result<mclBnG1, String> {
    unsafe {
        let mut g1: mclBnG1 = mem::zeroed();
        let ret = mclBnG1_hashAndMapTo(&mut g1, data.as_ptr() as *const _, data.len());
        if ret != 0 {
            Err("Failed to hash to G1".to_string())
        } else {
            Ok(g1)
        }
    }
}

pub fn hash_to_fr(data: &[u8]) -> Result<mclBnFr, String> {
    unsafe {
        let mut fr: mclBnFr = mem::zeroed();
        let ret = mclBnFr_setHashOf(&mut fr, data.as_ptr() as *const _, data.len());
        if ret != 0 {
            Err("Failed to hash to Fr".to_string())
        } else {
            Ok(fr)
        }
    }
}

pub fn pairing(p: &mclBnG1, q: &mclBnG2) -> mclBnGT {
    unsafe {
        let mut result: mclBnGT = mem::zeroed();
        mclBn_pairing(&mut result, p, q);
        result
    }
}

pub fn sign(data: &[u8], secret_key_hex: &str) -> Result<String, String> {
    unsafe {
        let sk_bytes = hex_to_bytes(secret_key_hex)?;

        let mut bls_sec: BlsSecretKey = mem::zeroed();
        let consumed = blsSecretKeyDeserialize(
            &mut bls_sec,
            sk_bytes.as_ptr() as *const _,
            sk_bytes.len(),
        );
        if consumed == 0 {
            return Err("Failed to deserialize secret key".to_string());
        }

        let mut hasher = Sha512::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let mut sig: BlsSignature = mem::zeroed();
        blsSign(&mut sig, &bls_sec, hash.as_ptr() as *const _, hash.len());

        let mut sig_buf = vec![0u8; BLS_SIGNATURE_SIZE];
        let sig_size = blsSignatureSerialize(
            sig_buf.as_mut_ptr() as *mut _,
            BLS_SIGNATURE_SIZE,
            &sig,
        );
        if sig_size == 0 {
            return Err("Failed to serialize signature".to_string());
        }

        Ok(bytes_to_hex(&sig_buf[..sig_size]))
    }
}

pub fn sign_direct(data: &[u8], secret_key_hex: &str) -> Result<String, String> {
    unsafe {
        let sk_bytes = hex_to_bytes(secret_key_hex)?;

        let mut bls_sec: BlsSecretKey = mem::zeroed();
        let consumed = blsSecretKeyDeserialize(
            &mut bls_sec,
            sk_bytes.as_ptr() as *const _,
            sk_bytes.len(),
        );
        if consumed == 0 {
            return Err("Failed to deserialize secret key".to_string());
        }

        let mut sig: BlsSignature = mem::zeroed();
        blsSign(&mut sig, &bls_sec, data.as_ptr() as *const _, data.len());

        let mut sig_buf = vec![0u8; BLS_SIGNATURE_SIZE];
        let sig_size = blsSignatureSerialize(
            sig_buf.as_mut_ptr() as *mut _,
            BLS_SIGNATURE_SIZE,
            &sig,
        );
        if sig_size == 0 {
            return Err("Failed to serialize signature".to_string());
        }

        Ok(bytes_to_hex(&sig_buf[..sig_size]))
    }
}
