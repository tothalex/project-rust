/* eslint-disable @typescript-eslint/no-explicit-any */
export interface IUnderlayingModule {
  HEAP8: Int8Array;
  HEAP32: Int32Array;

  // let mclBnFr_deserialize: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // let mclBnFr_serialize: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // let mclBnFr_setHashOf: ((...args: any[]) => any) | null = null; //_wrapInput
  // let getCurveOrder: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapGetStr
  // let getFieldOrder: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapGetStr
  // let blsIdSetDecStr: ((...args: any[]) => any) | null = null; //_wrapInput
  // let blsIdSetHexStr: ((...args: any[]) => any) | null = null; //_wrapInput
  // let blsIdGetDecStr: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapGetStr
  // let blsIdGetHexStr: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapGetStr
  // let blsIdSerialize: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // let blsSecretKeySerialize: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // let blsPublicKeySerialize: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // let blsSignatureSerialize: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // let blsIdDeserialize: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // let blsSecretKeyDeserialize: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // let blsPublicKeyDeserialize: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // let blsSignatureDeserialize: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // eslint-disable-next-line max-len
  // let blsPublicKeySerializeUncompressed: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // eslint-disable-next-line max-len
  // let blsSignatureSerializeUncompressed: ((x: number, ioMode?: number | undefined) => string | Uint8Array) | null = null; //_wrapSerialize
  // let blsPublicKeyDeserializeUncompressed: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // let blsSignatureDeserializeUncompressed: ((x: number, buf: Uint8Array) => void) | null = null; //_wrapDeserialize
  // let blsSecretKeySetLittleEndian: ((...args: any[]) => any) | null = null; //_wrapInput
  // let blsSecretKeySetLittleEndianMod: ((...args: any[]) => any) | null = null; //_wrapInput
  // let blsHashToSecretKey: ((...args: any[]) => any) | null = null; //_wrapInput
  // let blsSign: ((...args: any[]) => any) | null = null; //_wrapInput
  // let blsVerify: ((...args: any[]) => any) | null = null; //_wrapInput

  _mclBnMalloc: any;
  _mclBnFree: any;
  _mclBn_getVersion: any;
  _mclBn_init: any;
  _mclBn_getCurveType: any;
  _mclBn_getOpUnitSize: any;
  _mclBn_getG1ByteSize: any;
  _mclBn_getFpByteSize: any;
  _mclBn_getFrByteSize: any;
  _mclBn_getCurveOrder: any;
  _mclBn_getFieldOrder: any;
  _mclBn_setETHserialization: any;
  _mclBn_getETHserialization: any;
  _mclBn_setMapToMode: any;

  _mclBnFr_clear: any;
  _mclBnFr_setInt: any;
  _mclBnFr_setInt32: any;
  _mclBnFr_setStr: (...args: any[]) => any; //_wrapInput;
  _mclBnFr_setLittleEndian: (...args: any[]) => any; //_wrapInput;
  _mclBnFr_setBigEndianMod: (...args: any[]) => any; //_wrapInput;
  _mclBnFr_getLittleEndian: any;
  _mclBnFr_setLittleEndianMod: (...args: any[]) => any; //_wrapInput;
  _mclBnFr_deserialize: any;
  _mclBnFr_isValid: any;
  _mclBnFr_isEqual: any;
  _mclBnFr_isZero: any;
  _mclBnFr_isOne: any;
  _mclBnFr_isOdd: any;
  _mclBnFr_isNegative: any;
  _mclBnFr_setByCSPRNG: any;
  _mclBnFp_setByCSPRNG: any;
  _mclBn_setRandFunc: any;
  _mclBnFr_setHashOf: (...args: any[]) => any; //_wrapInput
  _mclBnFr_getStr: (
    x: number,
    ioMode?: number | undefined,
  ) => string | Uint8Array; //_wrapGetStr
  _mclBnFr_serialize: any;
  _mclBnFr_neg: (resultPos: number, xPos: number) => void;
  _mclBnFr_inv: (resultPos: number, xPos: number) => void;
  _mclBnFr_sqr: (resultPos: number, xPos: number) => void;
  _mclBnFr_add: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFr_sub: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFr_mul: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFr_div: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp_neg: (resultPos: number, xPos: number) => void;
  _mclBnFp_inv: (resultPos: number, xPos: number) => void;
  _mclBnFp_sqr: (resultPos: number, xPos: number) => void;
  _mclBnFp_add: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp_sub: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp_mul: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp_div: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp2_neg: (resultPos: number, xPos: number) => void;
  _mclBnFp2_inv: (resultPos: number, xPos: number) => void;
  _mclBnFp2_sqr: (resultPos: number, xPos: number) => void;
  _mclBnFp2_add: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp2_sub: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp2_mul: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFp2_div: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnFr_squareRoot: any;
  _mclBnFp_squareRoot: any;
  _mclBnFp2_squareRoot: any;
  _mclBnG1_clear: any;
  _mclBnG1_setStr: (...args: any[]) => any; //_wrapInput;
  _mclBnG1_deserialize: any;
  _mclBnG1_isValid: any;
  _mclBnG1_isEqual: any;
  _mclBnG1_isZero: any;
  _mclBnG1_isValidOrder: any;
  _mclBnG1_hashAndMapTo: (...args: any[]) => any; //_wrapInput;;
  _mclBnG1_getStr: (
    x: number,
    ioMode?: number | undefined,
  ) => string | Uint8Array; //_wrapGetStr;
  _mclBnG1_serialize: any;
  _mclBnG1_neg: (resultPos: number, xPos: number) => void;
  _mclBnG1_dbl: (resultPos: number, xPos: number) => void;
  _mclBnG1_normalize: (resultPos: number, xPos: number) => void;
  _mclBnG1_add: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnG1_sub: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnG1_mul: (resultPos: number, xPos: number, frPos: number) => void;
  _mclBnG1_mulCT: any;
  _mclBnG2_clear: any;
  _mclBnG2_setStr: (...args: any[]) => any; //_wrapInput;
  _mclBnG2_deserialize: any;
  _mclBnG2_isValid: any;
  _mclBnG2_isEqual: any;
  _mclBnG2_isZero: any;
  _mclBnG2_isValidOrder: any;
  _mclBnG2_hashAndMapTo: (...args: any[]) => any; //_wrapInput
  _mclBnG2_getStr: (
    x: number,
    ioMode?: number | undefined,
  ) => string | Uint8Array; //_wrapGetStr;
  _mclBnG2_serialize: any;
  _mclBnG2_neg: (resultPos: number, xPos: number) => void;
  _mclBnG2_dbl: (resultPos: number, xPos: number) => void;
  _mclBnG2_normalize: (resultPos: number, xPos: number) => void;
  _mclBnG2_add: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnG2_sub: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnG2_mul: (resultPos: number, xPos: number, frPos: number) => void;
  _mclBnG2_mulCT: any;
  _mclBnGT_clear: any;
  _mclBnGT_setInt: any;
  _mclBnGT_setInt32: any;
  _mclBnGT_setStr: (...args: any[]) => any; //_wrapInput;
  _mclBnGT_deserialize: any;
  _mclBnGT_isEqual: any;
  _mclBnGT_isZero: any;
  _mclBnGT_isOne: any;
  _mclBnGT_getStr: (
    x: number,
    ioMode?: number | undefined,
  ) => string | Uint8Array; //_wrapGetStr;
  _mclBnGT_serialize: any;
  _mclBnGT_neg: (resultPos: number, xPos: number) => void;
  _mclBnGT_inv: (resultPos: number, xPos: number) => void;
  _mclBnGT_invGeneric: any;
  _mclBnGT_sqr: (resultPos: number, xPos: number) => void;
  _mclBnGT_add: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnGT_sub: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnGT_mul: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnGT_div: (resultPos: number, xPos: number, yPos: number) => void;
  _mclBnGT_pow: any;
  _mclBnGT_powGeneric: any;
  _mclBnG1_mulVec: (
    resultG1Pos: number,
    G1ArrayPos: number,
    FRArrayPos: number,
  ) => void;
  _mclBnG2_mulVec: (
    resultG2Pos: number,
    G2ArrayPos: number,
    FRArrayPos: number,
  ) => void;
  _mclBnGT_powVec: any;
  _mclBn_pairing: (resultGTPos: number, g1Pos: number, g2Pos: number) => void;
  _mclBn_finalExp: (resultPos: number, xPos: number) => void;
  _mclBn_millerLoop: (
    resultGTPos: number,
    g1Pos: number,
    g2Pos: number,
  ) => void;
  _mclBn_millerLoopVec: any;
  _mclBn_getUint64NumToPrecompute: any;
  _mclBn_precomputeG2: any;
  _mclBn_precomputedMillerLoop: (
    resultPos: number,
    PPos: number,
    Qcoeff: number,
  ) => void;
  _mclBn_precomputedMillerLoop2: (
    resultPos: number,
    P1Pos: number,
    Q1coeff: number,
    P2Pos: number,
    Q2coeff: number,
  ) => void;
  _mclBn_precomputedMillerLoop2mixed: (
    resultPos: number,
    P1Pos: number,
    Q1Pos: number,
    P2Pos: number,
    Q2coeff: number,
  ) => void;
  _mclBn_FrLagrangeInterpolation: any;
  _mclBn_G1LagrangeInterpolation: any;
  _mclBn_G2LagrangeInterpolation: any;
  _mclBn_FrEvaluatePolynomial: any;
  _mclBn_G1EvaluatePolynomial: any;
  _mclBn_G2EvaluatePolynomial: any;
  _mclBn_verifyOrderG1: (doVerify: number) => void;
  _mclBn_verifyOrderG2: (doVerify: number) => void;

  _mclBnFp_setInt: any;
  _mclBnFp_setInt32: any;
  _mclBnFp_getStr: (
    x: number,
    ioMode?: number | undefined,
  ) => string | Uint8Array; //_wrapGetStr;
  _mclBnFp_setStr: (...args: any[]) => any; //_wrapInput;
  _mclBnFp_deserialize: any;
  _mclBnFp_serialize: any;
  _mclBnFp_clear: any;
  _mclBnFp_setLittleEndian: any;
  _mclBnFp_setLittleEndianMod: any;
  _mclBnFp_setBigEndianMod: any;
  _mclBnFp_getLittleEndian: any;
  _mclBnFp_isValid: any;
  _mclBnFp_isEqual: any;
  _mclBnFp_isZero: any;
  _mclBnFp_isOne: any;
  _mclBnFp_isOdd: any;
  _mclBnFp_isNegative: any;
  _mclBnFp_setHashOf: (...args: any[]) => any; //_wrapInput
  _mclBnFp_mapToG1: any;

  _mclBnFp2_deserialize: any;
  _mclBnFp2_serialize: any;
  _mclBnFp2_clear: any;
  _mclBnFp2_isEqual: any;
  _mclBnFp2_isZero: any;
  _mclBnFp2_isOne: any;
  _mclBnFp2_mapToG2: any;
  _mclBnG1_getBasePoint: any;

  _blsSetETHmode: any;
  _blsSetMapToMode: any;
  _blsInit: (curve: number, compiledTimeVar: number) => number;
  _blsSetETHserialization: any;
  _blsMalloc: any;
  _blsFree: any;
  _blsIdSetInt: any;
  _blsSecretKeySetLittleEndian: any;
  _blsSecretKeySetLittleEndianMod: any;
  _blsGetPublicKey: any;
  _blsHashToSignature: any;
  _blsSign: any;
  _blsVerify: any;
  _blsMultiVerifySub: any;
  _blsMultiVerifyFinal: any;
  _blsMultiVerify: any;
  _blsAggregateSignature: any;
  _blsSignatureAdd: any;
  _blsPublicKeyAdd: any;
  _blsFastAggregateVerify: any;
  _blsAggregateVerifyNoCheck: any;
  _blsIdSerialize: any;
  _blsSecretKeySerialize: any;
  _blsPublicKeySerialize: any;
  _blsSignatureSerialize: any;
  _blsIdDeserialize: any;
  _blsSecretKeyDeserialize: any;
  _blsPublicKeyDeserialize: any;
  _blsSignatureDeserialize: any;
  _blsIdIsEqual: any;
  _blsSecretKeyIsEqual: any;
  _blsPublicKeyIsEqual: any;
  _blsSignatureIsEqual: any;
  _blsIdIsZero: any;
  _blsSecretKeyIsZero: any;
  _blsPublicKeyIsZero: any;
  _blsSignatureIsZero: any;
  _blsSecretKeyShare: any;
  _blsPublicKeyShare: any;
  _blsSecretKeyRecover: any;
  _blsPublicKeyRecover: any;
  _blsSignatureRecover: any;
  _blsSecretKeyAdd: any;
  _blsSignatureVerifyOrder: any;
  _blsPublicKeyVerifyOrder: any;
  _blsSignatureIsValidOrder: any;
  _blsPublicKeyIsValidOrder: any;
  _blsVerifyAggregatedHashes: any;
  _blsSignHash: any;
  _blsPublicKeySerializeUncompressed: any;
  _blsSignatureSerializeUncompressed: any;
  _blsPublicKeyDeserializeUncompressed: any;
  _blsSignatureDeserializeUncompressed: any;
  _blsVerifyPairing: any;
  _blsVerifyHash: any;
  _blsSecretKeySub: any;
  _blsPublicKeySub: any;
  _blsSignatureSub: any;
  _blsSecretKeyNeg: any;
  _blsPublicKeyNeg: any;
  _blsSignatureNeg: any;
  _blsSecretKeyMul: any;
  _blsPublicKeyMul: any;
  _blsSignatureMul: any;
  _blsPublicKeyMulVec: any;
  _blsSignatureMulVec: any;
  _blsGetOpUnitSize: any;
  _blsGetCurveOrder: any;
  _blsGetFieldOrder: any;
  _blsGetSerializedSecretKeyByteSize: any;
  _blsGetFrByteSize: any;
  _blsGetSerializedPublicKeyByteSize: any;
  _blsGetG1ByteSize: any;
  _blsGetSerializedSignatureByteSize: any;
  _blsGetGeneratorOfPublicKey: any;
  _blsSetGeneratorOfPublicKey: any;
  _blsIdSetDecStr: any;
  _blsIdSetHexStr: any;
  _blsIdSetLittleEndian: any;
  _blsIdGetDecStr: any;
  _blsIdGetHexStr: any;
  _blsHashToSecretKey: any;
  _blsGetPop: any;
  _blsVerifyPop: any;
  _blsIdGetLittleEndian: any;
  _blsSecretKeySetDecStr: any;
  _blsSecretKeySetHexStr: any;
  _blsSecretKeyGetLittleEndian: any;
  _blsSecretKeyGetDecStr: any;
  _blsSecretKeyGetHexStr: any;
  _blsPublicKeySetHexStr: any;
  _blsPublicKeyGetHexStr: any;
  _blsSignatureSetHexStr: any;
  _blsSignatureGetHexStr: any;
  _blsDHKeyExchange: (
    resultPubKeyPos: number,
    secKeyPos: number,
    pubKeyPos: number,
  ) => void;
  _blsMultiAggregateSignature: any;
  _blsMultiAggregatePublicKey: any;
}
