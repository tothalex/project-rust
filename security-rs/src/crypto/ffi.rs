use std::os::raw::{c_int, c_void};

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mclBnFr {
    pub d: [u64; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mclBnG1 {
    pub x: mclBnFp,
    pub y: mclBnFp,
    pub z: mclBnFp,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mclBnG2 {
    pub x: mclBnFp2,
    pub y: mclBnFp2,
    pub z: mclBnFp2,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mclBnGT {
    pub d: [mclBnFp; 12],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mclBnFp {
    pub d: [u64; 6],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct mclBnFp2 {
    pub d: [mclBnFp; 2],
}

#[repr(C)]
pub struct BlsSecretKey {
    pub v: mclBnFr,
}

#[repr(C)]
pub struct BlsPublicKey {
    pub v: mclBnG2,
}

#[repr(C)]
pub struct BlsSignature {
    pub v: mclBnG1,
}

#[repr(C)]
pub struct BlsId {
    pub v: mclBnFr,
}

pub const MCL_BLS12_381: c_int = 5;
pub const MCLBN_COMPILED_TIME_VAR: c_int = 46;

#[link(name = "mcl", kind = "static")]
unsafe extern "C" {
    pub fn mclBn_init(curve: c_int, compiledTimeVar: c_int) -> c_int;
    pub fn blsInit(curve: c_int, compiledTimeVar: c_int) -> c_int;

    pub fn mclBnFr_setInt(y: *mut mclBnFr, x: i64);
    pub fn mclBnFr_setByCSPRNG(x: *mut mclBnFr) -> c_int;
    pub fn mclBnFr_setHashOf(x: *mut mclBnFr, buf: *const c_void, bufSize: usize) -> c_int;
    pub fn mclBnFr_deserialize(x: *mut mclBnFr, buf: *const c_void, bufSize: usize) -> usize;
    pub fn mclBnFr_serialize(buf: *mut c_void, maxBufSize: usize, x: *const mclBnFr) -> usize;
    pub fn mclBnFr_isEqual(x: *const mclBnFr, y: *const mclBnFr) -> c_int;
    pub fn mclBnFr_add(z: *mut mclBnFr, x: *const mclBnFr, y: *const mclBnFr);
    pub fn mclBnFr_sub(z: *mut mclBnFr, x: *const mclBnFr, y: *const mclBnFr);
    pub fn mclBnFr_mul(z: *mut mclBnFr, x: *const mclBnFr, y: *const mclBnFr);
    pub fn mclBnFr_div(z: *mut mclBnFr, x: *const mclBnFr, y: *const mclBnFr);

    pub fn mclBnG1_deserialize(x: *mut mclBnG1, buf: *const c_void, bufSize: usize) -> usize;
    pub fn mclBnG1_serialize(buf: *mut c_void, maxBufSize: usize, x: *const mclBnG1) -> usize;
    pub fn mclBnG1_hashAndMapTo(x: *mut mclBnG1, buf: *const c_void, bufSize: usize) -> c_int;
    pub fn mclBnG1_mul(z: *mut mclBnG1, x: *const mclBnG1, y: *const mclBnFr);
    pub fn mclBnG1_add(z: *mut mclBnG1, x: *const mclBnG1, y: *const mclBnG1);
    pub fn mclBnG1_isEqual(x: *const mclBnG1, y: *const mclBnG1) -> c_int;
    pub fn mclBnG2_deserialize(x: *mut mclBnG2, buf: *const c_void, bufSize: usize) -> usize;
    pub fn mclBnG2_serialize(buf: *mut c_void, maxBufSize: usize, x: *const mclBnG2) -> usize;
    pub fn mclBnG2_mul(z: *mut mclBnG2, x: *const mclBnG2, y: *const mclBnFr);
    pub fn mclBnG2_add(z: *mut mclBnG2, x: *const mclBnG2, y: *const mclBnG2);
    pub fn mclBnG2_isEqual(x: *const mclBnG2, y: *const mclBnG2) -> c_int;
    pub fn mclBnGT_mul(z: *mut mclBnGT, x: *const mclBnGT, y: *const mclBnGT);
    pub fn mclBnGT_isEqual(x: *const mclBnGT, y: *const mclBnGT) -> c_int;
    pub fn mclBnGT_serialize(buf: *mut c_void, maxBufSize: usize, x: *const mclBnGT) -> usize;

    pub fn mclBn_pairing(z: *mut mclBnGT, x: *const mclBnG1, y: *const mclBnG2);

    pub fn mclBn_FrEvaluatePolynomial(
        out: *mut mclBnFr,
        c_vec: *const mclBnFr,
        c_size: usize,
        x: *const mclBnFr,
    ) -> c_int;

    pub fn mclBn_FrLagrangeInterpolation(
        out: *mut mclBnFr,
        x_vec: *const mclBnFr,
        y_vec: *const mclBnFr,
        k: usize,
    ) -> c_int;

    pub fn blsSecretKeySetByCSPRNG(sec: *mut BlsSecretKey) -> c_int;
    pub fn blsSecretKeySerialize(
        buf: *mut c_void,
        maxBufSize: usize,
        sec: *const BlsSecretKey,
    ) -> usize;
    pub fn blsSecretKeyDeserialize(
        sec: *mut BlsSecretKey,
        buf: *const c_void,
        bufSize: usize,
    ) -> usize;
    pub fn blsSecretKeyShare(
        sec: *mut BlsSecretKey,
        msk: *const BlsSecretKey,
        k: usize,
        id: *const BlsId,
    ) -> c_int;
    pub fn blsSecretKeyRecover(
        sec: *mut BlsSecretKey,
        secVec: *const BlsSecretKey,
        idVec: *const BlsId,
        n: usize,
    ) -> c_int;

    pub fn blsGetPublicKey(pub_key: *mut BlsPublicKey, sec_key: *const BlsSecretKey);
    pub fn blsPublicKeySerialize(
        buf: *mut c_void,
        maxBufSize: usize,
        pub_key: *const BlsPublicKey,
    ) -> usize;
    pub fn blsPublicKeyDeserialize(
        pub_key: *mut BlsPublicKey,
        buf: *const c_void,
        bufSize: usize,
    ) -> usize;
    pub fn blsPublicKeyShare(
        pub_key: *mut BlsPublicKey,
        mpk: *const BlsPublicKey,
        k: usize,
        id: *const BlsId,
    ) -> c_int;
    pub fn blsPublicKeyRecover(
        pub_key: *mut BlsPublicKey,
        pubVec: *const BlsPublicKey,
        idVec: *const BlsId,
        n: usize,
    ) -> c_int;

    pub fn blsSign(
        sig: *mut BlsSignature,
        sec: *const BlsSecretKey,
        msg: *const c_void,
        msgSize: usize,
    );
    pub fn blsSignatureSerialize(
        buf: *mut c_void,
        maxBufSize: usize,
        sig: *const BlsSignature,
    ) -> usize;
    pub fn blsSignatureDeserialize(
        sig: *mut BlsSignature,
        buf: *const c_void,
        bufSize: usize,
    ) -> usize;
    pub fn blsIdDeserialize(id: *mut BlsId, buf: *const c_void, bufSize: usize) -> usize;
}

pub const FR_SIZE: usize = 32;
pub const G1_SIZE: usize = 48;
pub const G2_SIZE: usize = 96;
pub const GT_SIZE: usize = 576;
pub const BLS_SECRET_KEY_SIZE: usize = 32;
pub const BLS_SIGNATURE_SIZE: usize = 48;
