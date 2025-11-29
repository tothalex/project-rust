/* eslint-disable @typescript-eslint/no-explicit-any */
/// <reference types="../types/bls_c" />
import createModuleDefault from "bls-wasm/src/bls_c";
import createModuleETH from "bls-eth-wasm/src/bls_c";
import { randomFillSync } from "crypto";
import { IUnderlayingModule } from "./bls-helper-underlaying-module-interface";

const BASE_10 = 10;
const BASE_16 = 16;

let ethMode = false;

// const BN254 = 0;
// const BN381_1 = 1;
const BLS12_381 = 5;
// const ETH_MODE_DRAFT_05 = 1;
// const ETH_MODE_DRAFT_06 = 2;
const ETH_MODE_DRAFT_07 = 3;

const MCLBN_FR_UNIT_SIZE = 4;
const MCLBN_FP_UNIT_SIZE = 6;
let BLS_COMPILER_TIME_VAR_ADJ = ethMode ? 200 : 0;
let MCLBN_COMPILED_TIME_VAR =
  MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE + BLS_COMPILER_TIME_VAR_ADJ;

const MCLBN_FR_SIZE = MCLBN_FR_UNIT_SIZE * 8;
const MCLBN_FP_SIZE = MCLBN_FP_UNIT_SIZE * 8;
const MCLBN_G1_SIZE = MCLBN_FP_SIZE * 3;
const MCLBN_G2_SIZE = MCLBN_FP_SIZE * 6;
const MCLBN_GT_SIZE = MCLBN_FP_SIZE * 12;

const BLS_ID_SIZE = MCLBN_FR_SIZE;
const BLS_SECRETKEY_SIZE = MCLBN_FR_SIZE;
let BLS_PUBLICKEY_SIZE = MCLBN_FP_SIZE * 3 * (ethMode ? 1 : 2);
let BLS_SIGNATURE_SIZE = MCLBN_FP_SIZE * 3 * (ethMode ? 2 : 1);

let modRaw: IUnderlayingModule | null = null;

let getRandomValues = randomFillSync;

function _malloc(size: number, modx: IUnderlayingModule): number {
  return modx._blsMalloc(size);
}

function _free(pos: number, modx: IUnderlayingModule): void {
  modx._blsFree(pos);
}

// alloc new array
function _alloc(a_: Uint32Array, modx: IUnderlayingModule): number {
  return _malloc(a_.length * 4, modx);
}

// alloc and copy a_ to mod.HEAP32[pos / 4]
function _allocAndCopy(a_: Uint32Array, modx: IUnderlayingModule): number {
  const pos = _alloc(a_, modx);
  modx.HEAP32.set(a_, pos / 4);
  return pos;
}

// save pos to a_
function _save(a_: Uint32Array, pos: number, modx: IUnderlayingModule): void {
  a_.set(modx.HEAP32.subarray(pos / 4, pos / 4 + a_.length));
}

// save and free
function _saveAndFree(
  a_: Uint32Array,
  pos: number,
  modx: IUnderlayingModule,
): void {
  _save(a_, pos, modx);
  _free(pos, modx);
}

function _ptrToAsciiStr(
  pos: number,
  n: number,
  modx: IUnderlayingModule,
): string {
  let s = "";
  for (let i = 0; i < n; i++) {
    s += String.fromCharCode(modx.HEAP8[pos + i]);
  }
  return s;
}

function _asciiStrToPtr(
  pos: number,
  s: string,
  modx: IUnderlayingModule,
): void {
  for (let i = 0; i < s.length; i++) {
    modx.HEAP8[pos + i] = s.charCodeAt(i);
  }
}

function _toHex(a: Uint8Array, start: number, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) {
    s += ("0" + a[start + i].toString(BASE_16)).slice(-2);
  }
  return s;
}

// Uint8Array to hex string
function _toHexStr(a: Uint8Array): string {
  return _toHex(a, 0, a.length);
}

// hex string to Uint8Array
function _fromHexStr(s: string): Uint8Array {
  if (s.length & 1) {
    throw new Error("fromHexStr:length must be even " + s.length);
  }
  const n = s.length / 2;
  const a = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    a[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  }
  return a;
}

///////////////////////////
export function _copyToUint32Array(
  a: Uint32Array,
  pos: number,
  modx: IUnderlayingModule,
): void {
  a.set(modx.HEAP32.subarray(pos / 4, pos / 4 + a.length));
  //    for (let i = 0; i < a.length; i++) {
  //      a[i] = mod.HEAP32[pos / 4 + i]
  //    }
}

function _copyFromUint32Array(
  pos: number,
  a: Uint32Array,
  modx: IUnderlayingModule,
): void {
  modx.HEAP32.set(a, pos / 4);
  //    for (let i = 0; i < a.length; i++) {
  //      mod.HEAP32[pos / 4 + i] = a[i]
  //    }
}
//////////////////////////////////

function _wrapGetStr(
  func: any,
  returnAsStr: boolean,
  modx: IUnderlayingModule,
): (x: number, ioMode?: number) => string | Uint8Array {
  return (x: number, ioMode: number = 0): string | Uint8Array => {
    if (!modx) {
      throw new Error("Library not initiated!");
    }
    const maxBufSize = 3096;
    const pos = _malloc(maxBufSize, modx);
    const n = func(pos, maxBufSize, x, ioMode);
    if (n <= 0) {
      throw new Error("err gen_str:" + x);
    }
    let s = null;
    if (returnAsStr) {
      s = _ptrToAsciiStr(pos, n, modx);
    } else {
      s = new Uint8Array(modx.HEAP8.subarray(pos, pos + n));
    }
    _free(pos, modx);
    return s;
  };
}

function _wrapSerialize(
  func: any,
  modx: IUnderlayingModule,
): (x: number, ioMode?: number) => string | Uint8Array {
  return _wrapGetStr(func, false, modx);
}

function _wrapDeserialize(
  func: any,
  modx: IUnderlayingModule,
): (x: number, buf: Uint8Array) => void {
  return (x: number, buf: Uint8Array): void => {
    if (!modx) {
      throw new Error("Library not initiated!");
    }
    const pos = _malloc(buf.length, modx);
    modx.HEAP8.set(buf, pos);
    const r = func(x, pos, buf.length);
    _free(pos, modx);
    if (r === 0 || r !== buf.length) {
      throw new Error("err _wrapDeserialize");
    }
  };
}

/*
	argNum : n
	func(x0, ..., x_(n-1), buf, ioMode)
	=> func(x0, ..., x_(n-1), pos, buf.length, ioMode)
*/
function _wrapInput(
  func: any,
  argNum: number,
  returnValue: boolean,
  modx: IUnderlayingModule,
): (...args: any[]) => any {
  return function (...args: any[]): any {
    if (!modx) {
      throw new Error("Library not initiated!");
    }
    // const args = [...arguments];
    const buf = args[argNum];
    const typeStr = Object.prototype.toString.apply(buf);
    if (
      !["[object String]", "[object Uint8Array]", "[object Array]"].includes(
        typeStr,
      )
    ) {
      throw new Error(`err bad type:"${typeStr}". Use String or Uint8Array.`);
    }
    const ioMode = args[argNum + 1]; // may undefined
    const pos = _malloc(buf.length, modx);
    if (typeStr === "[object String]") {
      _asciiStrToPtr(pos, buf, modx);
    } else {
      modx.HEAP8.set(buf, pos);
    }
    const r = func(...args.slice(0, argNum), pos, buf.length, ioMode);
    _free(pos, modx);
    if (returnValue) {
      return r;
    }
    if (r) {
      throw new Error("err _wrapInput " + buf);
    }
  };
}

function _mulVec<T extends Common>(
  func: any,
  xVec: Common[],
  yVec: Common[],
  resultType: { new (): T },
  modx: IUnderlayingModule,
): T {
  const n = xVec.length;
  if (n != yVec.length) {
    throw new Error(`err _mulVec bad length ${n}, ${yVec.length}`);
  }
  const xSize = xVec[0].a_.length;
  const ySize = yVec[0].a_.length;
  const z = new resultType();
  const zPos = _alloc(z.a_, modx); //	const zPos = _malloc(z.a_.length * 4);
  _malloc(z.a_.length * 4, modx);
  const xPos = _malloc(xSize * n * 4, modx);
  const yPos = _malloc(ySize * n * 4, modx);
  let pos = xPos / 4;
  for (let i = 0; i < n; i++) {
    modx.HEAP32.set(xVec[i].a_, pos);
    pos += xSize;
  }
  pos = yPos / 4;
  for (let i = 0; i < n; i++) {
    modx.HEAP32.set(yVec[i].a_, pos);
    pos += ySize;
  }
  func(zPos, xPos, yPos, n);
  _free(yPos, modx);
  _free(xPos, modx);
  _saveAndFree(z.a_, zPos, modx);
  return z;
}

async function _init(isETH: boolean): Promise<void> {
  // createModuleETH;
  ethMode = isETH;

  BLS_COMPILER_TIME_VAR_ADJ = ethMode ? 200 : 0;
  MCLBN_COMPILED_TIME_VAR =
    MCLBN_FR_UNIT_SIZE * 10 + MCLBN_FP_UNIT_SIZE + BLS_COMPILER_TIME_VAR_ADJ;
  BLS_PUBLICKEY_SIZE = MCLBN_FP_SIZE * 3 * (ethMode ? 1 : 2);
  BLS_SIGNATURE_SIZE = MCLBN_FP_SIZE * 3 * (ethMode ? 2 : 1);

  let modTemp: any = null;
  if (isETH) {
    modTemp = await createModuleETH({
      cryptoGetRandomValues: getRandomValues,
    });
  } else {
    modTemp = await createModuleDefault({
      cryptoGetRandomValues: getRandomValues,
    });
  }
  if (!modTemp) {
    throw new Error("Could not load underlaying library (MCLBLS)");
  }
  const r = modTemp._blsInit(BLS12_381, MCLBN_COMPILED_TIME_VAR);
  if (r) {
    throw "blsInit err " + r;
  }
  if (isETH) {
    if (modTemp._blsSetETHmode(ETH_MODE_DRAFT_07) !== 0) {
      throw new Error(`bad setETHmode ${ETH_MODE_DRAFT_07}`);
    }
  }

  modRaw = {
    HEAP8: modTemp.HEAP8,
    HEAP32: modTemp.HEAP32,
    _mclBnMalloc: modTemp._mclBnMalloc,
    _mclBnFree: modTemp._mclBnFree,
    _mclBn_getVersion: modTemp._mclBn_getVersion,
    _mclBn_init: modTemp._mclBn_init,
    _mclBn_getCurveType: modTemp._mclBn_getCurveType,
    _mclBn_getOpUnitSize: modTemp._mclBn_getOpUnitSize,
    _mclBn_getG1ByteSize: modTemp._mclBn_getG1ByteSize,
    _mclBn_getFpByteSize: modTemp._mclBn_getFpByteSize,
    _mclBn_getFrByteSize: modTemp._mclBn_getFrByteSize,
    _mclBn_getCurveOrder: modTemp._mclBn_getCurveOrder,
    _mclBn_getFieldOrder: modTemp._mclBn_getFieldOrder,
    _mclBn_setETHserialization: modTemp._mclBn_setETHserialization,
    _mclBn_getETHserialization: modTemp._mclBn_getETHserialization,
    _mclBn_setMapToMode: modTemp._mclBn_setMapToMode,

    _mclBnFr_clear: modTemp._mclBnFr_clear,
    _mclBnFr_setInt: modTemp._mclBnFr_setInt,
    _mclBnFr_setInt32: modTemp._mclBnFr_setInt32,
    _mclBnFr_setStr: _wrapInput(modTemp._mclBnFr_setStr, 1, false, modTemp),
    _mclBnFr_setLittleEndian: _wrapInput(
      modTemp._mclBnFr_setLittleEndian,
      1,
      false,
      modTemp,
    ),
    _mclBnFr_setBigEndianMod: _wrapInput(
      modTemp._mclBnFr_setBigEndianMod,
      1,
      false,
      modTemp,
    ),
    _mclBnFr_getLittleEndian: modTemp._mclBnFr_getLittleEndian,
    _mclBnFr_setLittleEndianMod: _wrapInput(
      modTemp._mclBnFr_setLittleEndianMod,
      1,
      false,
      modTemp,
    ),
    _mclBnFr_deserialize: _wrapDeserialize(
      modTemp._mclBnFr_deserialize,
      modTemp,
    ),
    _mclBnFr_isValid: modTemp._mclBnFr_isValid,
    _mclBnFr_isEqual: modTemp._mclBnFr_isEqual,
    _mclBnFr_isZero: modTemp._mclBnFr_isZero,
    _mclBnFr_isOne: modTemp._mclBnFr_isOne,
    _mclBnFr_isOdd: modTemp._mclBnFr_isOdd,
    _mclBnFr_isNegative: modTemp._mclBnFr_isNegative,
    _mclBnFr_setByCSPRNG: modTemp._mclBnFr_setByCSPRNG,
    _mclBnFp_setByCSPRNG: modTemp._mclBnFp_setByCSPRNG,
    _mclBn_setRandFunc: modTemp._mclBn_setRandFunc,
    _mclBnFr_setHashOf: _wrapInput(
      modTemp._mclBnFr_setHashOf,
      1,
      false,
      modTemp,
    ),
    _mclBnFr_getStr: _wrapGetStr(modTemp._mclBnFr_getStr, false, modTemp),
    _mclBnFr_serialize: _wrapSerialize(modTemp._mclBnFr_serialize, modTemp),
    _mclBnFr_neg: modTemp._mclBnFr_neg,
    _mclBnFr_inv: modTemp._mclBnFr_inv,
    _mclBnFr_sqr: modTemp._mclBnFr_sqr,
    _mclBnFr_add: modTemp._mclBnFr_add,
    _mclBnFr_sub: modTemp._mclBnFr_sub,
    _mclBnFr_mul: modTemp._mclBnFr_mul,
    _mclBnFr_div: modTemp._mclBnFr_div,
    _mclBnFr_squareRoot: modTemp._mclBnFr_squareRoot,

    _mclBnFp_setInt: modTemp._mclBnFp_setInt,
    _mclBnFp_setInt32: modTemp._mclBnFp_setInt32,
    _mclBnFp_getStr: _wrapGetStr(modTemp._mclBnFp_getStr, true, modTemp),
    _mclBnFp_setStr: _wrapInput(modTemp._mclBnFp_setStr, 1, false, modTemp),
    _mclBnFp_deserialize: _wrapDeserialize(
      modTemp._mclBnFp_deserialize,
      modTemp,
    ),
    _mclBnFp_serialize: _wrapSerialize(modTemp._mclBnFp_serialize, modTemp),
    _mclBnFp_clear: modTemp._mclBnFp_clear,
    _mclBnFp_setLittleEndian: _wrapInput(
      modTemp._mclBnFp_setLittleEndian,
      1,
      false,
      modTemp,
    ),
    _mclBnFp_setLittleEndianMod: _wrapInput(
      modTemp._mclBnFp_setLittleEndianMod,
      1,
      false,
      modTemp,
    ),
    _mclBnFp_setBigEndianMod: _wrapInput(
      modTemp._mclBnFp_setBigEndianMod,
      1,
      false,
      modTemp,
    ),
    _mclBnFp_getLittleEndian: modTemp._mclBnFp_getLittleEndian,
    _mclBnFp_isValid: modTemp._mclBnFp_isValid,
    _mclBnFp_isEqual: modTemp._mclBnFp_isEqual,
    _mclBnFp_isZero: modTemp._mclBnFp_isZero,
    _mclBnFp_isOne: modTemp._mclBnFp_isOne,
    _mclBnFp_isOdd: modTemp._mclBnFp_isOdd,
    _mclBnFp_isNegative: modTemp._mclBnFp_isNegative,
    _mclBnFp_setHashOf: _wrapInput(
      modTemp._mclBnFp_setHashOf,
      1,
      false,
      modTemp,
    ),
    _mclBnFp_mapToG1: modTemp._mclBnFp_mapToG1,
    _mclBnFp_neg: modTemp._mclBnFp_neg,
    _mclBnFp_inv: modTemp._mclBnFp_inv,
    _mclBnFp_sqr: modTemp._mclBnFp_sqr,
    _mclBnFp_add: modTemp._mclBnFp_add,
    _mclBnFp_sub: modTemp._mclBnFp_sub,
    _mclBnFp_mul: modTemp._mclBnFp_mul,
    _mclBnFp_div: modTemp._mclBnFp_div,
    _mclBnFp_squareRoot: modTemp._mclBnFp_squareRoot,

    _mclBnFp2_deserialize: _wrapDeserialize(
      modTemp._mclBnFp2_deserialize,
      modTemp,
    ),
    _mclBnFp2_serialize: _wrapSerialize(modTemp._mclBnFp2_serialize, modTemp),
    _mclBnFp2_clear: modTemp._mclBnFp2_clear,
    _mclBnFp2_isEqual: modTemp._mclBnFp2_isEqual,
    _mclBnFp2_isZero: modTemp._mclBnFp2_isZero,
    _mclBnFp2_isOne: modTemp._mclBnFp2_isOne,
    _mclBnFp2_mapToG2: modTemp._mclBnFp2_mapToG2,
    _mclBnFp2_neg: modTemp._mclBnFp2_neg,
    _mclBnFp2_inv: modTemp._mclBnFp2_inv,
    _mclBnFp2_sqr: modTemp._mclBnFp2_sqr,
    _mclBnFp2_add: modTemp._mclBnFp2_add,
    _mclBnFp2_sub: modTemp._mclBnFp2_sub,
    _mclBnFp2_mul: modTemp._mclBnFp2_mul,
    _mclBnFp2_div: modTemp._mclBnFp2_div,
    _mclBnFp2_squareRoot: modTemp._mclBnFp2_squareRoot,

    _mclBnG1_clear: modTemp._mclBnG1_clear,
    _mclBnG1_setStr: _wrapInput(modTemp._mclBnG1_setStr, 1, false, modTemp),
    _mclBnG1_getStr: _wrapGetStr(modTemp._mclBnG1_getStr, true, modTemp),
    _mclBnG1_deserialize: _wrapDeserialize(
      modTemp._mclBnG1_deserialize,
      modTemp,
    ),
    _mclBnG1_serialize: _wrapSerialize(modTemp._mclBnG1_serialize, modTemp),
    _mclBnG1_isValid: modTemp._mclBnG1_isValid,
    _mclBnG1_isEqual: modTemp._mclBnG1_isEqual,
    _mclBnG1_isZero: modTemp._mclBnG1_isZero,
    _mclBnG1_isValidOrder: modTemp._mclBnG1_isValidOrder,
    _mclBnG1_hashAndMapTo: _wrapInput(
      modTemp._mclBnG1_hashAndMapTo,
      1,
      false,
      modTemp,
    ),
    _mclBnG1_neg: modTemp._mclBnG1_neg,
    _mclBnG1_dbl: modTemp._mclBnG1_dbl,
    _mclBnG1_normalize: modTemp._mclBnG1_normalize,
    _mclBnG1_add: modTemp._mclBnG1_add,
    _mclBnG1_sub: modTemp._mclBnG1_sub,
    _mclBnG1_mul: modTemp._mclBnG1_mul,
    _mclBnG1_mulCT: modTemp._mclBnG1_mulCT,
    _mclBnG1_getBasePoint: modTemp._mclBnG1_getBasePoint,

    _mclBnG2_clear: modTemp._mclBnG2_clear,
    _mclBnG2_setStr: _wrapInput(modTemp._mclBnG2_setStr, 1, false, modTemp),
    _mclBnG2_getStr: _wrapGetStr(modTemp._mclBnG2_getStr, true, modTemp),
    _mclBnG2_deserialize: _wrapDeserialize(
      modTemp._mclBnG2_deserialize,
      modTemp,
    ),
    _mclBnG2_serialize: _wrapSerialize(modTemp._mclBnG2_serialize, modTemp),
    _mclBnG2_isValid: modTemp._mclBnG2_isValid,
    _mclBnG2_isEqual: modTemp._mclBnG2_isEqual,
    _mclBnG2_isZero: modTemp._mclBnG2_isZero,
    _mclBnG2_isValidOrder: modTemp._mclBnG2_isValidOrder,
    _mclBnG2_hashAndMapTo: _wrapInput(
      modTemp._mclBnG2_hashAndMapTo,
      1,
      false,
      modTemp,
    ),
    _mclBnG2_neg: modTemp._mclBnG2_neg,
    _mclBnG2_dbl: modTemp._mclBnG2_dbl,
    _mclBnG2_normalize: modTemp._mclBnG2_normalize,
    _mclBnG2_add: modTemp._mclBnG2_add,
    _mclBnG2_sub: modTemp._mclBnG2_sub,
    _mclBnG2_mul: modTemp._mclBnG2_mul,
    _mclBnG2_mulCT: modTemp._mclBnG2_mulCT,

    _mclBnGT_clear: modTemp._mclBnGT_clear,
    _mclBnGT_setInt: modTemp._mclBnGT_setInt,
    _mclBnGT_setInt32: modTemp._mclBnGT_setInt32,
    _mclBnGT_setStr: _wrapInput(modTemp._mclBnGT_setStr, 1, false, modTemp),
    _mclBnGT_getStr: _wrapGetStr(modTemp._mclBnGT_getStr, true, modTemp),
    _mclBnGT_deserialize: _wrapDeserialize(
      modTemp._mclBnGT_deserialize,
      modTemp,
    ),
    _mclBnGT_serialize: _wrapSerialize(modTemp._mclBnGT_serialize, modTemp),
    _mclBnGT_isEqual: modTemp._mclBnGT_isEqual,
    _mclBnGT_isZero: modTemp._mclBnGT_isZero,
    _mclBnGT_isOne: modTemp._mclBnGT_isOne,
    _mclBnGT_neg: modTemp._mclBnGT_neg,
    _mclBnGT_inv: modTemp._mclBnGT_inv,
    _mclBnGT_invGeneric: modTemp._mclBnGT_invGeneric,
    _mclBnGT_sqr: modTemp._mclBnGT_sqr,
    _mclBnGT_add: modTemp._mclBnGT_add,
    _mclBnGT_sub: modTemp._mclBnGT_sub,
    _mclBnGT_mul: modTemp._mclBnGT_mul,
    _mclBnGT_div: modTemp._mclBnGT_div,
    _mclBnGT_pow: modTemp._mclBnGT_pow,
    _mclBnGT_powGeneric: modTemp._mclBnGT_powGeneric,
    _mclBnG1_mulVec: modTemp._mclBnG1_mulVec,
    _mclBnG2_mulVec: modTemp._mclBnG2_mulVec,
    _mclBnGT_powVec: modTemp._mclBnGT_powVec,

    _mclBn_pairing: modTemp._mclBn_pairing,
    _mclBn_finalExp: modTemp._mclBn_finalExp,
    _mclBn_millerLoop: modTemp._mclBn_millerLoop,
    _mclBn_millerLoopVec: modTemp._mclBn_millerLoopVec,
    _mclBn_getUint64NumToPrecompute: modTemp._mclBn_getUint64NumToPrecompute,
    _mclBn_precomputeG2: modTemp._mclBn_precomputeG2,
    _mclBn_precomputedMillerLoop: modTemp._mclBn_precomputedMillerLoop,
    _mclBn_precomputedMillerLoop2: modTemp._mclBn_precomputedMillerLoop2,
    _mclBn_precomputedMillerLoop2mixed:
      modTemp._mclBn_precomputedMillerLoop2mixed,
    _mclBn_FrLagrangeInterpolation: modTemp._mclBn_FrLagrangeInterpolation,
    _mclBn_G1LagrangeInterpolation: modTemp._mclBn_G1LagrangeInterpolation,
    _mclBn_G2LagrangeInterpolation: modTemp._mclBn_G2LagrangeInterpolation,
    _mclBn_FrEvaluatePolynomial: modTemp._mclBn_FrEvaluatePolynomial,
    _mclBn_G1EvaluatePolynomial: modTemp._mclBn_G1EvaluatePolynomial,
    _mclBn_G2EvaluatePolynomial: modTemp._mclBn_G2EvaluatePolynomial,
    _mclBn_verifyOrderG1: modTemp._mclBn_verifyOrderG1,
    _mclBn_verifyOrderG2: modTemp._mclBn_verifyOrderG2,

    _blsSetETHmode: modTemp._blsSetETHmode,
    _blsSetMapToMode: modTemp._blsSetMapToMode,
    _blsInit: modTemp._blsInit,
    _blsSetETHserialization: modTemp._blsSetETHserialization,
    _blsMalloc: modTemp._blsMalloc,
    _blsFree: modTemp._blsFree,

    /**
     * ID related Stuff
     */
    _blsIdSetInt: modTemp._blsIdSetInt,
    _blsIdSerialize: _wrapSerialize(modTemp._blsIdSerialize, modTemp),
    _blsIdDeserialize: _wrapDeserialize(modTemp._blsIdDeserialize, modTemp),
    _blsIdIsZero: modTemp._blsIdIsZero,
    _blsIdIsEqual: modTemp._blsIdIsEqual,
    _blsIdSetDecStr: _wrapInput(modTemp._blsIdSetDecStr, 1, false, modTemp),
    _blsIdSetHexStr: _wrapInput(modTemp._blsIdSetHexStr, 1, false, modTemp),
    _blsIdGetDecStr: _wrapGetStr(modTemp._blsIdGetDecStr, false, modTemp),
    _blsIdGetHexStr: _wrapGetStr(modTemp._blsIdGetHexStr, false, modTemp),
    _blsIdSetLittleEndian: modTemp._blsIdSetLittleEndian,
    _blsIdGetLittleEndian: modTemp._blsIdGetLittleEndian,

    /**
     * SecretKey related Stuff
     */
    _blsSecretKeySerialize: _wrapSerialize(
      modTemp._blsSecretKeySerialize,
      modTemp,
    ),
    _blsSecretKeyDeserialize: _wrapDeserialize(
      modTemp._blsSecretKeyDeserialize,
      modTemp,
    ),
    _blsSecretKeyIsEqual: modTemp._blsSecretKeyIsEqual,
    _blsSecretKeyIsZero: modTemp._blsSecretKeyIsZero,
    _blsSecretKeySetDecStr: modTemp._blsSecretKeySetDecStr,
    _blsSecretKeySetHexStr: modTemp._blsSecretKeySetHexStr,
    _blsSecretKeyGetDecStr: modTemp._blsSecretKeyGetDecStr,
    _blsSecretKeyGetHexStr: modTemp._blsSecretKeyGetHexStr,
    _blsSecretKeySetLittleEndian: _wrapInput(
      modTemp._blsSecretKeySetLittleEndian,
      1,
      false,
      modTemp,
    ),
    _blsSecretKeySetLittleEndianMod: _wrapInput(
      modTemp._blsSecretKeySetLittleEndianMod,
      1,
      false,
      modTemp,
    ),
    _blsSecretKeyGetLittleEndian: modTemp._blsSecretKeyGetLittleEndian,
    _blsGetPublicKey: modTemp._blsGetPublicKey,
    _blsGetPop: modTemp._blsGetPop, //Aláírja saját maga a publikus kucslát, kvázi self sign
    _blsSecretKeyShare: modTemp._blsSecretKeyShare,
    _blsSecretKeyRecover: modTemp._blsSecretKeyRecover,
    _blsDHKeyExchange: modTemp._blsDHKeyExchange,
    _blsSecretKeyAdd: modTemp._blsSecretKeyAdd,
    _blsSecretKeySub: modTemp._blsSecretKeySub,
    _blsSecretKeyNeg: modTemp._blsSecretKeyNeg,
    _blsSecretKeyMul: modTemp._blsSecretKeyMul,
    _blsHashToSecretKey: _wrapInput(
      modTemp._blsHashToSecretKey,
      1,
      false,
      modTemp,
    ),

    /**
     * PublicKey related Stuff
     */
    _blsPublicKeySerialize: _wrapSerialize(
      modTemp._blsPublicKeySerialize,
      modTemp,
    ),
    _blsPublicKeyDeserialize: _wrapDeserialize(
      modTemp._blsPublicKeyDeserialize,
      modTemp,
    ),
    _blsPublicKeySerializeUncompressed: _wrapSerialize(
      modTemp._blsPublicKeySerializeUncompressed,
      modTemp,
    ),
    _blsPublicKeyDeserializeUncompressed: _wrapDeserialize(
      modTemp._blsPublicKeyDeserializeUncompressed,
      modTemp,
    ),
    _blsPublicKeyIsEqual: modTemp._blsPublicKeyIsEqual,
    _blsPublicKeyIsZero: modTemp._blsPublicKeyIsZero,
    _blsPublicKeySetHexStr: modTemp._blsPublicKeySetHexStr,
    _blsPublicKeyGetHexStr: modTemp._blsPublicKeyGetHexStr,

    _blsPublicKeyShare: modTemp._blsPublicKeyShare,
    _blsPublicKeyRecover: modTemp._blsPublicKeyRecover,

    _blsSign: _wrapInput(modTemp._blsSign, 2, false, modTemp),
    _blsSignHash: _wrapInput(modTemp._blsSignHash, 2, false, modTemp),

    _blsPublicKeyVerifyOrder: modTemp._blsPublicKeyVerifyOrder,
    _blsPublicKeyIsValidOrder: modTemp._blsPublicKeyIsValidOrder,

    _blsPublicKeyAdd: modTemp._blsPublicKeyAdd,
    _blsPublicKeySub: modTemp._blsPublicKeySub,
    _blsPublicKeyNeg: modTemp._blsPublicKeyNeg,
    _blsPublicKeyMul: modTemp._blsPublicKeyMul,
    _blsPublicKeyMulVec: modTemp._blsPublicKeyMulVec,

    _blsGetGeneratorOfPublicKey: modTemp._blsGetGeneratorOfPublicKey,
    _blsSetGeneratorOfPublicKey: modTemp._blsSetGeneratorOfPublicKey,

    /**
     * Signature related Stuff
     */
    _blsSignatureSerialize: _wrapSerialize(
      modTemp._blsSignatureSerialize,
      modTemp,
    ),
    _blsSignatureDeserialize: _wrapDeserialize(
      modTemp._blsSignatureDeserialize,
      modTemp,
    ),
    _blsSignatureSerializeUncompressed: _wrapSerialize(
      modTemp._blsSignatureSerializeUncompressed,
      modTemp,
    ),
    _blsSignatureDeserializeUncompressed: _wrapDeserialize(
      modTemp._blsSignatureDeserializeUncompressed,
      modTemp,
    ),
    _blsSignatureIsEqual: modTemp._blsSignatureIsEqual,
    _blsSignatureIsZero: modTemp._blsSignatureIsZero,
    _blsSignatureSetHexStr: modTemp._blsSignatureSetHexStr,
    _blsSignatureGetHexStr: modTemp._blsSignatureGetHexStr,

    _blsSignatureRecover: modTemp._blsSignatureRecover,

    _blsSignatureVerifyOrder: modTemp._blsSignatureVerifyOrder,
    _blsSignatureIsValidOrder: modTemp._blsSignatureIsValidOrder,

    _blsSignatureAdd: modTemp._blsSignatureAdd,
    _blsSignatureSub: modTemp._blsSignatureSub,
    _blsSignatureNeg: modTemp._blsSignatureNeg,
    _blsSignatureMul: modTemp._blsSignatureMul,
    _blsSignatureMulVec: modTemp._blsSignatureMulVec,

    _blsVerify: _wrapInput(modTemp._blsVerify, 2, true, modTemp),
    _blsVerifyPop: modTemp._blsVerifyPop, //check self signed public key
    _blsVerifyHash: _wrapInput(modTemp._blsVerifyHash, 2, true, modTemp),

    _blsMultiVerifySub: modTemp._blsMultiVerifySub,
    _blsMultiVerifyFinal: modTemp._blsMultiVerifyFinal,
    _blsMultiVerify: modTemp._blsMultiVerify,

    _blsFastAggregateVerify: modTemp._blsFastAggregateVerify,
    _blsAggregateVerifyNoCheck: modTemp._blsAggregateVerifyNoCheck,
    _blsVerifyAggregatedHashes: modTemp._blsVerifyAggregatedHashes,
    _blsVerifyPairing: modTemp._blsVerifyPairing,

    _blsHashToSignature: modTemp._blsHashToSignature,
    _blsAggregateSignature: modTemp._blsAggregateSignature,

    _blsGetOpUnitSize: modTemp._blsGetOpUnitSize,
    _blsGetCurveOrder: _wrapGetStr(modTemp._blsGetCurveOrder, false, modTemp),
    _blsGetFieldOrder: _wrapGetStr(modTemp._blsGetFieldOrder, false, modTemp),
    _blsGetSerializedSecretKeyByteSize:
      modTemp._blsGetSerializedSecretKeyByteSize,
    _blsGetFrByteSize: modTemp._blsGetFrByteSize,
    _blsGetSerializedPublicKeyByteSize:
      modTemp._blsGetSerializedPublicKeyByteSize,
    _blsGetG1ByteSize: modTemp._blsGetG1ByteSize,
    _blsGetSerializedSignatureByteSize:
      modTemp._blsGetSerializedSignatureByteSize,
    _blsMultiAggregateSignature: modTemp._blsMultiAggregateSignature,
    _blsMultiAggregatePublicKey: modTemp._blsMultiAggregatePublicKey,
  };

  BLS.setETHserialization(ethMode);
}

abstract class Common {
  protected get mod(): IUnderlayingModule {
    if (modRaw) {
      return modRaw;
    } else {
      throw new Error("Library not initialized!");
    }
  }

  public a_: Uint32Array;

  constructor(size: number) {
    this.a_ = new Uint32Array(size / 4);
  }

  abstract deserialize(s: Uint8Array): void;

  abstract serialize(): Uint8Array;

  public deserializeHexStr(s: string): void {
    this.deserialize(_fromHexStr(s));
  }

  public serializeToHexStr(): string {
    return _toHexStr(this.serialize());
  }

  public clear(): void {
    this.a_.fill(0);
  }

  public clone<T extends Common>(): T {
    const copy = new (this.constructor as new () => this)() as unknown as T;
    copy.a_ = this.a_.slice(0);
    return copy;
  }

  abstract isEqual(rhs: this): boolean;

  abstract isZero(): boolean;

  abstract neg(): Common;

  abstract add(x: Common): Common;

  abstract sub(x: Common): Common;

  abstract mul(x: Common): Common;

  // set parameter (p1, p2 may be undefined)
  protected _setter(func: any, p1: unknown, p2: unknown): void {
    const pos = _alloc(this.a_, this.mod);
    const r = func(pos, p1, p2);
    _saveAndFree(this.a_, pos, this.mod);
    if (r) {
      throw new Error("_setter err");
    }
  }

  // getter (p1, p2 may be undefined)
  protected _getter<T>(func: any, p1: unknown, p2: unknown): T {
    const pos = _allocAndCopy(this.a_, this.mod);
    const s = func(pos, p1, p2);
    _free(pos, this.mod);
    return s;
  }

  protected _isEqual(
    func: (x: number, y: number) => number,
    rhs: Common,
  ): boolean {
    const xPos = _allocAndCopy(this.a_, this.mod);
    const yPos = _allocAndCopy(rhs.a_, this.mod);
    const r = func(xPos, yPos);
    _free(yPos, this.mod);
    _free(xPos, this.mod);
    return r === 1;
  }

  // func(y, this) and return y
  protected _op1<T extends Common>(func: any, resultType: { new (): T }): T {
    const y = new resultType();
    const xPos = _allocAndCopy(this.a_, this.mod);
    const yPos = _alloc(y.a_, this.mod);
    func(yPos, xPos);
    _saveAndFree(y.a_, yPos, this.mod);
    _free(xPos, this.mod);
    return y;
  }

  // func(z, this, y) and return z
  protected _op2<T extends Common>(
    func: any,
    y: Common,
    resultType: { new (): T },
  ): T {
    const z = new resultType();
    // const z = new resultType();
    const xPos = _allocAndCopy(this.a_, this.mod);
    const yPos = _allocAndCopy(y.a_, this.mod);
    const zPos = _alloc(z.a_, this.mod);
    func(zPos, xPos, yPos);
    _saveAndFree(z.a_, zPos, this.mod);
    _free(yPos, this.mod);
    _free(xPos, this.mod);
    return z;
  }

  // func(self, y)
  protected _update(func: any, y: Common): void {
    const xPos = _allocAndCopy(this.a_, this.mod);
    const yPos = _allocAndCopy(y.a_, this.mod);
    func(xPos, yPos);
    _free(yPos, this.mod);
    _saveAndFree(this.a_, xPos, this.mod);
  }

  // devide Uint32Array a into n and chose the idx-th
  protected _getSubArray(idx: number, n: number): Uint32Array {
    const d = this.a_.length / n;
    return new Uint32Array(this.a_.buffer, d * idx * 4, d);
  }

  // set array lhs to idx
  protected _setSubArray(lhs: Common, idx: number, n: number): void {
    const d = this.a_.length / n;
    this.a_.set(lhs.a_, d * idx);
  }
}

// Common	Common2	IntType	EllipticType

abstract class ExtendedCommon extends Common {
  abstract setStr(s: string, base?: number): void;
  abstract getStr(base?: number): string;
}

abstract class IntType extends ExtendedCommon {
  // setint
  abstract setInt(x: number): void;
  abstract override setStr(s: string, base: number): void;
  abstract override getStr(base: number): string;
  abstract setLittleEndian(s: Uint8Array): void;
  abstract setLittleEndianMod(s: Uint8Array): void;
  abstract setByCSPRNG(): void;
}

abstract class EllipticType extends ExtendedCommon {
  abstract setHashOf(s: string | Uint8Array): void;
  abstract normalize(): void;
  abstract isValid(): boolean;
  abstract isValidOrder(): boolean;
}

export class Fr extends IntType {
  constructor() {
    super(MCLBN_FR_SIZE);
  }

  public setInt(x: number): void {
    this._setter(this.mod._mclBnFr_setInt32, x, undefined);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._mclBnFr_deserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._mclBnFr_serialize, undefined, undefined);
  }

  public setStr(s: string, base = 0): void {
    this._setter(this.mod._mclBnFr_setStr, s, base);
  }

  public getStr(base = 0): string {
    return this._getter(this.mod._mclBnFr_getStr, base, undefined);
  }

  public isZero(): boolean {
    return this._getter(this.mod._mclBnFr_isZero, undefined, undefined) === 1;
  }

  public isOne(): boolean {
    return this._getter(this.mod._mclBnFr_isOne, undefined, undefined) === 1;
  }

  public isEqual(rhs: Fr): boolean {
    return this._isEqual(this.mod._mclBnFr_isEqual, rhs);
  }

  public setLittleEndian(s: Uint8Array): void {
    this._setter(this.mod._mclBnFr_setLittleEndian, s, undefined);
  }

  public setLittleEndianMod(s: Uint8Array): void {
    this._setter(this.mod._mclBnFr_setLittleEndianMod, s, undefined);
  }

  public setBigEndianMod(s: Uint8Array): void {
    this._setter(this.mod._mclBnFr_setBigEndianMod, s, undefined);
  }

  public setByCSPRNG(): void {
    const a = new Uint8Array(MCLBN_FR_SIZE);
    getRandomValues(a);
    this.setLittleEndian(a);
  }

  public setHashOf(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnFr_setHashOf, s, undefined);
  }

  public inv(): Fr {
    this.a_ = this._op1(this.mod._mclBnFr_inv, Fr).a_;
    return this;
  }

  public neg(): Fr {
    this.a_ = this._op1(this.mod._mclBnFr_neg, Fr).a_;
    return this;
  }

  public add(x: Fr): Fr {
    this.a_ = this._op2(this.mod._mclBnFr_add, x, Fr).a_;
    return this;
  }

  public sub(x: Fr): Fr {
    this.a_ = this._op2(this.mod._mclBnFr_sub, x, Fr).a_;
    return this;
  }

  public mul(x: Fr): Fr {
    this.a_ = this._op2(this.mod._mclBnFr_mul, x, Fr).a_;
    return this;
  }

  public div(x: Fr): Fr {
    this.a_ = this._op2(this.mod._mclBnFr_div, x, Fr).a_;
    return this;
  }
}

export class Fp extends IntType {
  constructor() {
    super(MCLBN_FP_SIZE);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._mclBnFp_deserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._mclBnFp_serialize, undefined, undefined);
  }

  public isEqual(rhs: this): boolean {
    return this._isEqual(this.mod._mclBnFp_isEqual, rhs);
  }

  public isZero(): boolean {
    return this._getter(this.mod._mclBnFp_isZero, undefined, undefined) === 1;
  }

  public isOne(): boolean {
    return this._getter(this.mod._mclBnFp_isOne, undefined, undefined) === 1;
  }

  public setInt(x: number): void {
    this._setter(this.mod._mclBnFp_setInt32, x, undefined);
  }

  public setStr(s: string, base: number): void {
    this._setter(this.mod._mclBnFp_setStr, s, base);
  }

  public getStr(base: number): string {
    return this._getter(this.mod._mclBnFp_getStr, base, undefined);
  }

  public setLittleEndian(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnFp_setLittleEndian, s, undefined);
  }

  public setLittleEndianMod(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnFp_setLittleEndianMod, s, undefined);
  }

  public setBigEndianMod(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnFp_setBigEndianMod, s, undefined);
  }

  public setByCSPRNG(): void {
    const a = new Uint8Array(MCLBN_FP_SIZE);
    getRandomValues(a);
    this.setLittleEndian(a);
  }

  public setHashOf(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnFp_setHashOf, s, undefined);
  }

  public mapToG1(): G1 {
    const y = new G1();
    const xPos = _allocAndCopy(this.a_, this.mod);
    const yPos = _alloc(y.a_, this.mod);
    this.mod._mclBnFp_mapToG1(yPos, xPos);
    _saveAndFree(y.a_, yPos, this.mod);
    _free(xPos, this.mod);
    return y;
  }

  public neg(): Fp {
    this.a_ = this._op1(this.mod._mclBnFp_neg, Fp).a_;
    return this;
  }

  public add(x: Fp): Fp {
    this.a_ = this._op2(this.mod._mclBnFp_add, x, Fp).a_;
    return this;
  }

  public sub(x: Fp): Fp {
    this.a_ = this._op2(this.mod._mclBnFp_sub, x, Fp).a_;
    return this;
  }

  public mul(x: Fp): Fp {
    this.a_ = this._op2(this.mod._mclBnFp_mul, x, Fp).a_;
    return this;
  }
}

export class Fp2 extends ExtendedCommon {
  constructor() {
    super(MCLBN_FP_SIZE * 2);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._mclBnFp2_deserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._mclBnFp2_serialize, undefined, undefined);
  }

  public isEqual(rhs: this): boolean {
    return this._isEqual(this.mod._mclBnFp2_isEqual, rhs);
  }

  public isZero(): boolean {
    return this._getter(this.mod._mclBnFp2_isZero, undefined, undefined) === 1;
  }

  public isOne(): boolean {
    return this._getter(this.mod._mclBnFp2_isOne, undefined, undefined) === 1;
  }

  public setInt(x: number, y: number): void {
    const v = new Fp();
    v.setInt(x);
    this.set_a(v);
    v.setInt(y);
    this.set_b(v);
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public setStr(_s: string, _base?: number): void {
    throw new Error("Method not supported.");
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  public getStr(_base?: number): string {
    throw new Error("Method not supported.");
  }

  public mapToG2(): G2 {
    const y = new G2();
    const xPos = _allocAndCopy(this.a_, this.mod);
    const yPos = _alloc(y.a_, this.mod);
    this.mod._mclBnFp2_mapToG2(yPos, xPos);
    _saveAndFree(y.a_, yPos, this.mod);
    _free(xPos, this.mod);
    return y;
  }

  // x = a + bi where a, b in Fp and i^2 = -1
  public get_a(): Fp {
    const r = new Fp();
    r.a_ = this._getSubArray(0, 2);
    return r;
  }

  public get_b(): Fp {
    const r = new Fp();
    r.a_ = this._getSubArray(1, 2);
    return r;
  }

  public set_a(v: Fp): void {
    this._setSubArray(v, 0, 2);
  }

  public set_b(v: Fp): void {
    this._setSubArray(v, 1, 2);
  }

  public neg(): Fp2 {
    this.a_ = this._op1(this.mod._mclBnFp2_neg, Fp2).a_;
    return this;
  }

  public add(x: Fp2): Fp2 {
    this.a_ = this._op2(this.mod._mclBnFp2_add, x, Fp2).a_;
    return this;
  }

  public sub(x: Fp2): Fp2 {
    this.a_ = this._op2(this.mod._mclBnFp2_sub, x, Fp2).a_;
    return this;
  }

  public mul(x: Fp2): Fp2 {
    this.a_ = this._op2(this.mod._mclBnFp2_mul, x, Fp2).a_;
    return this;
  }
}

export class G1 extends EllipticType {
  constructor() {
    super(MCLBN_G1_SIZE);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._mclBnG1_deserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._mclBnG1_serialize, undefined, undefined);
  }

  public isEqual(rhs: this): boolean {
    return this._isEqual(this.mod._mclBnG1_isEqual, rhs);
  }

  public isZero(): boolean {
    return this._getter(this.mod._mclBnG1_isZero, undefined, undefined) === 1;
  }

  public setStr(s: string, base?: number): void {
    this._setter(this.mod._mclBnG1_setStr, s, base);
  }

  public getStr(base?: number): string {
    return this._getter(this.mod._mclBnG1_getStr, base, undefined);
  }

  public normalize(): void {
    this.a_ = this._op1(this.mod._mclBnG1_normalize, G1).a_;
  }

  public isValid(): boolean {
    return this._getter(this.mod._mclBnG1_isValid, undefined, undefined) === 1;
  }

  public isValidOrder(): boolean {
    return (
      this._getter(this.mod._mclBnG1_isValidOrder, undefined, undefined) === 1
    );
  }

  public setHashOf(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnG1_hashAndMapTo, s, undefined);
  }

  public getX(): Fp {
    const r = new Fp();
    r.a_ = this._getSubArray(0, 3);
    return r;
  }

  public getY(): Fp {
    const r = new Fp();
    r.a_ = this._getSubArray(1, 3);
    return r;
  }

  public getZ(): Fp {
    const r = new Fp();
    r.a_ = this._getSubArray(2, 3);
    return r;
  }

  public setX(v: Fp): void {
    this._setSubArray(v, 0, 3);
  }

  public setY(v: Fp): void {
    this._setSubArray(v, 1, 3);
  }

  public setZ(v: Fp): void {
    this._setSubArray(v, 2, 3);
  }

  public to<T extends Lagrangable>(resultType: { new (): T }): T {
    const a = new resultType();
    if (!ethMode && a instanceof PublicKey) {
      throw new Error("BLS initialized: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && a instanceof Signature) {
      throw new Error("BLS initialized: G1 is PublicKey; G2 is Signature");
    }
    a.a_ = this.a_.slice(0);
    return a;
  }

  public from(x: PublicKey): void;
  public from(x: Signature): void;
  public from(x: Lagrangable): void {
    if (!ethMode && x instanceof PublicKey) {
      throw new Error("BLS initialized as: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && x instanceof Signature) {
      throw new Error("BLS initialized as: G1 is PublicKey; G2 is Signature");
    }
    this.a_ = x.a_.slice(0);
  }

  public neg(): G1 {
    this.a_ = this._op1(this.mod._mclBnG1_neg, G1).a_;
    return this;
  }

  public add(x: G1): G1 {
    this.a_ = this._op2(this.mod._mclBnG1_add, x, G1).a_;
    return this;
  }

  public sub(x: G1): G1 {
    this.a_ = this._op2(this.mod._mclBnG1_sub, x, G1).a_;
    return this;
  }

  public mul(x: Fr): G1 {
    this.a_ = this._op2(this.mod._mclBnG1_mul, x, G1).a_;
    return this;
  }
}

export class G2 extends EllipticType {
  constructor() {
    super(MCLBN_G2_SIZE);
  }

  deserialize(s: Uint8Array): void {
    this._setter(this.mod._mclBnG2_deserialize, s, undefined);
  }

  serialize(): Uint8Array {
    return this._getter(this.mod._mclBnG2_serialize, undefined, undefined);
  }

  isEqual(rhs: this): boolean {
    return this._isEqual(this.mod._mclBnG2_isEqual, rhs);
  }

  isZero(): boolean {
    return this._getter(this.mod._mclBnG2_isZero, undefined, undefined) === 1;
  }

  setStr(s: string, base?: number): void {
    this._setter(this.mod._mclBnG2_setStr, s, base);
  }

  getStr(base?: number): string {
    return this._getter(this.mod._mclBnG2_getStr, base, undefined);
  }

  normalize(): void {
    this.a_ = this._op1(this.mod._mclBnG2_normalize, G2).a_;
  }

  isValid(): boolean {
    return this._getter(this.mod._mclBnG2_isValid, undefined, undefined) === 1;
  }

  isValidOrder(): boolean {
    return (
      this._getter(this.mod._mclBnG2_isValidOrder, undefined, undefined) === 1
    );
  }

  setHashOf(s: string | Uint8Array): void {
    this._setter(this.mod._mclBnG2_hashAndMapTo, s, undefined);
  }

  getX(): Fp2 {
    const r = new Fp2();
    r.a_ = this._getSubArray(0, 3);
    return r;
  }

  getY(): Fp2 {
    const r = new Fp2();
    r.a_ = this._getSubArray(1, 3);
    return r;
  }

  getZ(): Fp2 {
    const r = new Fp2();
    r.a_ = this._getSubArray(2, 3);
    return r;
  }

  setX(v: Fp2): void {
    this._setSubArray(v, 0, 3);
  }

  setY(v: Fp2): void {
    this._setSubArray(v, 1, 3);
  }

  setZ(v: Fp2): void {
    this._setSubArray(v, 2, 3);
  }

  public to<T extends Lagrangable>(resultType: { new (): T }): T {
    const a = new resultType();
    if (!ethMode && a instanceof Signature) {
      throw new Error("BLS initialized: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && a instanceof PublicKey) {
      throw new Error("BLS initialized: G1 is PublicKey; G2 is Signature");
    }
    a.a_ = this.a_.slice(0);
    return a;
  }

  public from(x: PublicKey): void;
  public from(x: Signature): void;
  public from(x: Common): void {
    if (!ethMode && x instanceof Signature) {
      throw new Error("BLS initialized as: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && x instanceof PublicKey) {
      throw new Error("BLS initialized as: G1 is PublicKey; G2 is Signature");
    }
    this.a_ = x.a_.slice(0);
  }

  public neg(): G2 {
    this.a_ = this._op1(this.mod._mclBnG2_neg, G2).a_;
    return this;
  }

  public add(x: G2): G2 {
    this.a_ = this._op2(this.mod._mclBnG2_add, x, G2).a_;
    return this;
  }

  public sub(x: G2): G2 {
    this.a_ = this._op2(this.mod._mclBnG2_sub, x, G2).a_;
    return this;
  }

  public mul(x: Fr): G2 {
    this.a_ = this._op2(this.mod._mclBnG2_mul, x, G2).a_;
    return this;
  }
}

export class GT extends ExtendedCommon {
  constructor() {
    super(MCLBN_GT_SIZE);
  }

  deserialize(s: Uint8Array): void {
    this._setter(this.mod._mclBnGT_deserialize, s, undefined);
  }

  serialize(): Uint8Array {
    return this._getter(this.mod._mclBnGT_serialize, undefined, undefined);
  }

  isEqual(rhs: this): boolean {
    return this._isEqual(this.mod._mclBnGT_isEqual, rhs);
  }

  isZero(): boolean {
    return this._getter(this.mod._mclBnGT_isZero, undefined, undefined) === 1;
  }

  isOne(): boolean {
    return this._getter(this.mod._mclBnGT_isOne, undefined, undefined) === 1;
  }

  setInt(x: number): void {
    this._setter(this.mod._mclBnGT_setInt32, x, undefined);
  }

  setStr(s: string, base?: number): void {
    this._setter(this.mod._mclBnGT_setStr, s, base);
  }

  getStr(base?: number): string {
    return this._getter(this.mod._mclBnGT_getStr, base, undefined);
  }

  public neg(): GT {
    this.a_ = this._op1(this.mod._mclBnGT_neg, GT).a_;
    return this;
  }

  public add(x: GT): GT {
    this.a_ = this._op2(this.mod._mclBnGT_add, x, GT).a_;
    return this;
  }

  public sub(x: GT): GT {
    this.a_ = this._op2(this.mod._mclBnGT_sub, x, GT).a_;
    return this;
  }

  public mul(x: GT): GT {
    this.a_ = this._op2(this.mod._mclBnGT_mul, x, GT).a_;
    return this;
  }
}

export class Id extends IntType {
  constructor() {
    super(BLS_ID_SIZE);
  }

  public setInt(x: number): void {
    this._setter(this.mod._blsIdSetInt, x, undefined);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._blsIdDeserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._blsIdSerialize, undefined, undefined);
  }

  public setStr(s: string, base = 10): void {
    switch (base) {
      case BASE_10:
        this._setter(this.mod._blsIdSetDecStr, s, undefined);
        return;
      case BASE_16:
        this._setter(this.mod._blsIdSetHexStr, s, undefined);
        return;
      default:
        throw "BlsId.setStr:bad base:" + base;
    }
  }

  public getStr(base = 10): string {
    switch (base) {
      case BASE_10:
        return this._getter(this.mod._blsIdGetDecStr, undefined, undefined);
      case BASE_16:
        return this._getter(this.mod._blsIdGetHexStr, undefined, undefined);
      default:
        throw "BlsId.getStr:bad base:" + base;
    }
  }

  public isZero(): boolean {
    //TODO: ellenőrini, hogy működik-e! Az ID elvileg FR!!!
    return this._getter(this.mod._mclBnFr_isZero, undefined, undefined) === 1;
  }

  public isOne(): boolean {
    //TODO: ellenőrini, hogy működik-e! Az ID elvileg FR!!!
    return this._getter(this.mod._mclBnFr_isOne, undefined, undefined) === 1;
  }

  public isEqual(rhs: Id): boolean {
    return this._isEqual(this.mod._blsIdIsEqual, rhs);
  }

  public setLittleEndian(s: Uint8Array): void {
    this._setter(this.mod._blsSecretKeySetLittleEndian, s, undefined);
  }

  setLittleEndianMod(s: Uint8Array): void {
    this._setter(this.mod._blsSecretKeySetLittleEndianMod, s, undefined);
  }

  public setByCSPRNG(): void {
    const a = new Uint8Array(BLS_ID_SIZE);
    getRandomValues(a);
    this.setLittleEndian(a);
  }

  public setHashOf(s: string | Uint8Array): void {
    //TODO: ellenőrini, hogy működik-e! Az ID elvileg FR!!!
    this._setter(this.mod._mclBnFr_setHashOf, s, undefined);
  }

  public neg(): Id {
    this.a_ = this._op1(this.mod._mclBnFr_neg, Id).a_;
    return this;
  }

  public add(x: Id): Id {
    this.a_ = this._op2(this.mod._mclBnFr_add, x, Id).a_;
    return this;
  }

  public sub(x: Id): Id {
    this.a_ = this._op2(this.mod._mclBnFr_sub, x, Id).a_;
    return this;
  }

  public mul(x: Id): Id {
    this.a_ = this._op2(this.mod._mclBnFr_mul, x, Id).a_;
    return this;
  }
}

abstract class Lagrangable extends Common {
  protected callShare(
    func: any,
    a: Lagrangable,
    size: number,
    vec: Lagrangable[],
    id: Id,
  ): void {
    const pos = _allocAndCopy(a.a_, this.mod);
    const idPos = _allocAndCopy(id.a_, this.mod);
    const vecPos = _malloc(size * vec.length, this.mod);
    for (let i = 0; i < vec.length; i++) {
      _copyFromUint32Array(vecPos + size * i, vec[i].a_, this.mod);
    }
    func(pos, vecPos, vec.length, idPos);
    _free(vecPos, this.mod);
    _free(idPos, this.mod);
    _saveAndFree(a.a_, pos, this.mod);
  }

  protected callRecover(
    func: any,
    a: Lagrangable,
    size: number,
    vec: Lagrangable[],
    idVec: Id[],
  ): void {
    const n = vec.length;
    if (n != idVec.length) {
      throw "recover:bad length";
    }
    const secPos = _alloc(a.a_, this.mod);
    const vecPos = _malloc(size * n, this.mod);
    const idVecPos = _malloc(BLS_ID_SIZE * n, this.mod);
    for (let i = 0; i < n; i++) {
      _copyFromUint32Array(vecPos + size * i, vec[i].a_, this.mod);
      _copyFromUint32Array(idVecPos + BLS_ID_SIZE * i, idVec[i].a_, this.mod);
    }
    const r = func(secPos, vecPos, idVecPos, n);
    _free(idVecPos, this.mod);
    _free(vecPos, this.mod);
    _saveAndFree(a.a_, secPos, this.mod);
    if (r) {
      throw "callRecover";
    }
  }
}

export class SecretKey extends Lagrangable {
  constructor() {
    super(BLS_SECRETKEY_SIZE);
  }

  public setInt(x: number): void {
    this._setter(this.mod._blsIdSetInt, x, undefined); // same as Id
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._blsSecretKeyDeserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._blsSecretKeySerialize, undefined, undefined);
  }

  public setStr(s: string, base = 0): void {
    //TODO: ellenőrini, hogy működik-e! Az ID elvileg FR!!!
    this._setter(this.mod._mclBnFr_setStr, s, base);
  }

  public getStr(base = 0): string {
    //TODO: ellenőrini, hogy működik-e! Az ID elvileg FR!!!
    return this._getter(this.mod._mclBnFr_getStr, base, undefined);
  }

  public isZero(): boolean {
    return (
      this._getter(this.mod._blsSecretKeyIsZero, undefined, undefined) === 1
    );
  }

  public isOne(): boolean {
    //TODO: ellenőrini, hogy működik-e! Az ID elvileg FR!!!
    return this._getter(this.mod._mclBnFr_isOne, undefined, undefined) === 1;
  }

  public isEqual(rhs: SecretKey): boolean {
    return this._isEqual(this.mod._blsSecretKeyIsEqual, rhs);
  }

  public setLittleEndian(s: Uint8Array): void {
    this._setter(this.mod._blsSecretKeySetLittleEndian, s, undefined);
  }

  public setLittleEndianMod(s: Uint8Array): void {
    this._setter(this.mod._blsSecretKeySetLittleEndianMod, s, undefined);
  }

  public setByCSPRNG(): void {
    const a = new Uint8Array(BLS_SECRETKEY_SIZE);
    getRandomValues(a);
    this.setLittleEndian(a);
  }

  public setHashOf(s: string | Uint8Array): void {
    this._setter(this.mod._blsHashToSecretKey, s, undefined);
  }

  public share(msk: SecretKey[], id: Id): void {
    this.callShare(
      this.mod._blsSecretKeyShare,
      this,
      BLS_SECRETKEY_SIZE,
      msk,
      id,
    );
  }

  public recover(secVec: SecretKey[], idVec: Id[]): void {
    this.callRecover(
      this.mod._blsSecretKeyRecover,
      this,
      BLS_SECRETKEY_SIZE,
      secVec,
      idVec,
    );
  }

  public getPublicKey(): PublicKey {
    const pub = new PublicKey();
    const secPos = _allocAndCopy(this.a_, this.mod);
    const pubPos = _alloc(pub.a_, this.mod);
    this.mod._blsGetPublicKey(pubPos, secPos);
    _saveAndFree(pub.a_, pubPos, this.mod);
    _free(secPos, this.mod);
    return pub;
  }

  /*
	input
	m : message (string or Uint8Array)
	return
	BlsSignature
	*/
  public sign(m: string | Uint8Array): Signature {
    const sig = new Signature();
    const secPos = _allocAndCopy(this.a_, this.mod);
    const sigPos = _alloc(sig.a_, this.mod);
    this.mod._blsSign(sigPos, secPos, m);
    _saveAndFree(sig.a_, sigPos, this.mod);
    _free(secPos, this.mod);
    return sig;
  }

  public signHash(hash: string | Uint8Array): Signature {
    const sig = new Signature();
    const secPos = _allocAndCopy(this.a_, this.mod);
    const sigPos = _alloc(sig.a_, this.mod);
    this.mod._blsSignHash(sigPos, secPos, hash);
    _saveAndFree(sig.a_, sigPos, this.mod);
    _free(secPos, this.mod);
    return sig;
  }

  public getDHKeyExchange(pubKey: PublicKey): PublicKey {
    const resultPubKey = new PublicKey();
    const secPos = _allocAndCopy(this.a_, this.mod);
    const resultPubKeyPos = _alloc(resultPubKey.a_, this.mod);
    const pubKeyPos = _allocAndCopy(pubKey.a_, this.mod);
    // blsDHKeyExchange(pub, this, pubKey)
    this.mod._blsDHKeyExchange(resultPubKeyPos, secPos, pubKeyPos);
    _saveAndFree(resultPubKey.a_, resultPubKeyPos, this.mod);
    _free(secPos, this.mod);
    _free(pubKeyPos, this.mod);
    return resultPubKey;
  }

  public to<T extends Fr>(resultType: { new (): T }): T {
    const a = new resultType();
    a.a_ = this.a_.slice(0);
    return a;
  }

  public from(x: Fr): void {
    this.a_ = x.a_.slice(0);
  }

  public neg(): SecretKey {
    this.a_ = this._op1(this.mod._mclBnFr_neg, SecretKey).a_;
    return this;
  }

  public add(rhs: SecretKey): SecretKey {
    this._update(this.mod._blsSecretKeyAdd, rhs);
    return this;
  }

  public sub(x: SecretKey): SecretKey {
    this.a_ = this._op2(this.mod._mclBnFr_sub, x, SecretKey).a_;
    return this;
  }

  public mul(x: SecretKey): SecretKey {
    this.a_ = this._op2(this.mod._mclBnFr_mul, x, SecretKey).a_;
    return this;
  }
}

//Ez vagy G1 vagy G2
export class PublicKey extends Lagrangable {
  constructor() {
    super(BLS_PUBLICKEY_SIZE);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._blsPublicKeyDeserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._blsPublicKeySerialize, undefined, undefined);
  }

  public deserializeUncompressed(s: Uint8Array): void {
    this._setter(this.mod._blsPublicKeyDeserializeUncompressed, s, undefined);
  }

  public serializeUncompressed(): Uint8Array {
    return this._getter(
      this.mod._blsPublicKeySerializeUncompressed,
      undefined,
      undefined,
    );
  }

  public isZero(): boolean {
    return (
      this._getter(this.mod._blsPublicKeyIsZero, undefined, undefined) === 1
    );
  }

  public isEqual(rhs: PublicKey): boolean {
    return this._isEqual(this.mod._blsPublicKeyIsEqual, rhs);
  }

  public share(msk: PublicKey[], id: Id): void {
    this.callShare(
      this.mod._blsPublicKeyShare,
      this,
      BLS_PUBLICKEY_SIZE,
      msk,
      id,
    );
  }

  public recover(secVec: PublicKey[], idVec: Id[]): void {
    this.callRecover(
      this.mod._blsPublicKeyRecover,
      this,
      BLS_PUBLICKEY_SIZE,
      secVec,
      idVec,
    );
  }

  public isValidOrder(): boolean {
    return (
      this._getter(this.mod._blsPublicKeyIsValidOrder, undefined, undefined) ===
      1
    );
  }

  public verify(sig: Signature, m: string | Uint8Array): boolean {
    const pubPos = _allocAndCopy(this.a_, this.mod);
    const sigPos = _allocAndCopy(sig.a_, this.mod);
    const r = this.mod._blsVerify(sigPos, pubPos, m, undefined);
    _free(sigPos, this.mod);
    _free(pubPos, this.mod);
    return r != 0;
  }

  public verifyHash(sig: Signature, m: string | Uint8Array): boolean {
    const pubPos = _allocAndCopy(this.a_, this.mod);
    const sigPos = _allocAndCopy(sig.a_, this.mod);
    const r = this.mod._blsVerifyHash(sigPos, pubPos, m, undefined);
    _free(sigPos, this.mod);
    _free(pubPos, this.mod);
    return r != 0;
  }

  public to<T extends EllipticType>(resultType: { new (): T }): T {
    const a = new resultType();
    if (!ethMode && a instanceof G1) {
      throw new Error("BLS initialized: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && a instanceof G2) {
      throw new Error("BLS initialized: G1 is PublicKey; G2 is Signature");
    }
    a.a_ = this.a_.slice(0);
    return a;
  }

  public from(x: G1): void;
  public from(x: G2): void;
  public from(x: EllipticType): void {
    if (!ethMode && x instanceof G1) {
      throw new Error("BLS initialized as: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && x instanceof G2) {
      throw new Error("BLS initialized as: G1 is PublicKey; G2 is Signature");
    }
    this.a_ = x.a_.slice(0);
  }

  public neg(): PublicKey {
    if (ethMode) {
      this.a_ = this._op1(this.mod._mclBnG1_neg, PublicKey).a_;
    } else {
      this.a_ = this._op1(this.mod._mclBnG2_neg, PublicKey).a_;
    }
    return this;
  }

  public add(rhs: PublicKey): PublicKey {
    this._update(this.mod._blsPublicKeyAdd, rhs);
    return this;
  }

  public sub(x: PublicKey): PublicKey {
    if (ethMode) {
      this.a_ = this._op2(this.mod._mclBnG1_sub, x, PublicKey).a_;
    } else {
      this.a_ = this._op2(this.mod._mclBnG2_sub, x, PublicKey).a_;
    }
    return this;
  }

  public mul(x: SecretKey): PublicKey {
    if (ethMode) {
      this.a_ = this._op2(this.mod._mclBnG1_mul, x, PublicKey).a_;
    } else {
      this.a_ = this._op2(this.mod._mclBnG2_mul, x, PublicKey).a_;
    }
    return this;
  }
}

//Ez vagy G1 vagy G2
export class Signature extends Lagrangable {
  constructor() {
    super(BLS_SIGNATURE_SIZE);
  }

  public deserialize(s: Uint8Array): void {
    this._setter(this.mod._blsSignatureDeserialize, s, undefined);
  }

  public serialize(): Uint8Array {
    return this._getter(this.mod._blsSignatureSerialize, undefined, undefined);
  }

  public deserializeUncompressed(s: Uint8Array): void {
    this._setter(this.mod._blsSignatureDeserializeUncompressed, s, undefined);
  }

  public serializeUncompressed(): Uint8Array {
    return this._getter(
      this.mod._blsSignatureSerializeUncompressed,
      undefined,
      undefined,
    );
  }

  public isZero(): boolean {
    return (
      this._getter(this.mod._blsSignatureIsZero, undefined, undefined) === 1
    );
  }

  public isEqual(rhs: Signature): boolean {
    return this._isEqual(this.mod._blsSignatureIsEqual, rhs);
  }

  public recover(secVec: Signature[], idVec: Id[]): void {
    this.callRecover(
      this.mod._blsSignatureRecover,
      this,
      BLS_SIGNATURE_SIZE,
      secVec,
      idVec,
    );
  }

  public isValidOrder(): boolean {
    return (
      this._getter(this.mod._blsSignatureIsValidOrder, undefined, undefined) ===
      1
    );
  }

  // this = aggSig
  public aggregate(sigVec: Signature[]): boolean {
    const n = sigVec.length;
    const aggSigPos = _allocAndCopy(this.a_, this.mod);
    const sigVecPos = _malloc(BLS_SIGNATURE_SIZE * n, this.mod);
    for (let i = 0; i < n; i++) {
      this.mod.HEAP32.set(
        sigVec[i].a_,
        (sigVecPos + BLS_SIGNATURE_SIZE * i) / 4,
      );
    }
    const r = this.mod._blsAggregateSignature(aggSigPos, sigVecPos, n);
    _free(sigVecPos, this.mod);
    _saveAndFree(this.a_, aggSigPos, this.mod);
    return r === 1;
  }

  // this = aggSig
  public fastAggregateVerify(pubVec: PublicKey[], msg: Uint8Array): boolean {
    const n = pubVec.length;
    const msgSize = msg.length;
    const aggSigPos = _allocAndCopy(this.a_, this.mod);
    const pubVecPos = _malloc(BLS_PUBLICKEY_SIZE * n, this.mod);
    const msgPos = _malloc(msgSize, this.mod);
    for (let i = 0; i < n; i++) {
      this.mod.HEAP32.set(
        pubVec[i].a_,
        (pubVecPos + BLS_PUBLICKEY_SIZE * i) / 4,
      );
    }
    this.mod.HEAP8.set(msg, msgPos);
    const r = this.mod._blsFastAggregateVerify(
      aggSigPos,
      pubVecPos,
      n,
      msgPos,
      msgSize,
    );
    _free(msgPos, this.mod);
    _free(pubVecPos, this.mod);
    _free(aggSigPos, this.mod);
    return r === 1;
  }

  // this = aggSig
  // msgVec = (32 * pubVec.length)-size Uint8Array
  public aggregateVerifyNoCheck(
    pubVec: PublicKey[],
    msgVec: Uint8Array,
  ): boolean {
    const n = pubVec.length;
    const msgSize = 32;
    if (n == 0 || msgVec.length != msgSize * n) {
      return false;
    }
    const aggSigPos = _allocAndCopy(this.a_, this.mod);
    const pubVecPos = _malloc(BLS_PUBLICKEY_SIZE * n, this.mod);
    const msgPos = _malloc(msgVec.length, this.mod);
    for (let i = 0; i < n; i++) {
      this.mod.HEAP32.set(
        pubVec[i].a_,
        (pubVecPos + BLS_PUBLICKEY_SIZE * i) / 4,
      );
    }
    this.mod.HEAP8.set(msgVec, msgPos);
    const r = this.mod._blsAggregateVerifyNoCheck(
      aggSigPos,
      pubVecPos,
      msgPos,
      msgSize,
      n,
    );
    _free(msgPos, this.mod);
    _free(pubVecPos, this.mod);
    _free(aggSigPos, this.mod);
    return r == 1;
  }

  public to<T extends EllipticType>(resultType: { new (): T }): T {
    const a = new resultType();
    if (!ethMode && a instanceof G2) {
      throw new Error("BLS initialized: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && a instanceof G1) {
      throw new Error("BLS initialized: G1 is PublicKey; G2 is Signature");
    }
    a.a_ = this.a_.slice(0);
    return a;
  }

  public from(x: G1): void;
  public from(x: G2): void;
  public from(x: EllipticType): void {
    if (!ethMode && x instanceof G2) {
      throw new Error("BLS initialized as: G1 is Signature; G2 is PublicKey");
    }
    if (ethMode && x instanceof G1) {
      throw new Error("BLS initialized as: G1 is PublicKey; G2 is Signature");
    }
    this.a_ = x.a_.slice(0);
  }

  public neg(): Signature {
    if (ethMode) {
      this.a_ = this._op1(this.mod._mclBnG2_neg, Signature).a_;
    } else {
      this.a_ = this._op1(this.mod._mclBnG1_neg, Signature).a_;
    }
    return this;
  }

  public add(rhs: Signature): Signature {
    this._update(this.mod._blsSignatureAdd, rhs);
    return this;
  }

  public sub(x: Signature): Signature {
    if (ethMode) {
      this.a_ = this._op2(this.mod._mclBnG2_sub, x, Signature).a_;
    } else {
      this.a_ = this._op2(this.mod._mclBnG1_sub, x, Signature).a_;
    }
    return this;
  }

  public mul(x: SecretKey): Signature {
    if (ethMode) {
      this.a_ = this._op2(this.mod._mclBnG2_mul, x, Signature).a_;
    } else {
      this.a_ = this._op2(this.mod._mclBnG1_mul, x, Signature).a_;
    }
    return this;
  }
}

export class PrecomputedG2 {
  private static get mod(): IUnderlayingModule {
    if (modRaw) {
      return modRaw;
    } else {
      throw new Error("Library not initialized!");
    }
  }

  public p: number | null;

  constructor(Q: G2) {
    const byteSize = PrecomputedG2.mod._mclBn_getUint64NumToPrecompute() * 8;
    this.p = _malloc(byteSize, PrecomputedG2.mod);
    const Qpos = _allocAndCopy(Q.a_, PrecomputedG2.mod);
    PrecomputedG2.mod._mclBn_precomputeG2(this.p, Qpos);
    _free(Qpos, PrecomputedG2.mod);
  }

  /*
		call destroy if PrecomputedG2 is not necessary
		to avoid memory leak
	*/
  public destroy(): void {
    if (this.p) {
      _free(this.p, PrecomputedG2.mod);
      this.p = null;
    }
  }
}

export class BLS {
  private static get mod(): IUnderlayingModule {
    if (modRaw) {
      return modRaw;
    } else {
      throw new Error("Library not initialized!");
    }
  }

  private static _op0<T extends Common>(
    func: any,
    resultType: { new (): T },
  ): T {
    const y = new resultType();
    const yPos = _alloc(y.a_, BLS.mod);
    func(yPos);
    _saveAndFree(y.a_, yPos, BLS.mod);
    return y;
  }

  private static _op1<T extends Common>(
    func: any,
    x: Common,
    resultType: { new (): T },
  ): T {
    const y = new resultType();
    const xPos = _allocAndCopy(x.a_, BLS.mod);
    const yPos = _alloc(y.a_, BLS.mod);
    func(yPos, xPos);
    _saveAndFree(y.a_, yPos, BLS.mod);
    _free(xPos, BLS.mod);
    return y;
  }

  // func(z, this, y) and return z
  private static _op2<T extends Common>(
    func: any,
    x: Common,
    y: Common,
    resultType: { new (): T },
  ): T {
    const z = new resultType();
    const xPos = _allocAndCopy(x.a_, BLS.mod);
    const yPos = _allocAndCopy(y.a_, BLS.mod);
    const zPos = _alloc(z.a_, BLS.mod);
    func(zPos, xPos, yPos);
    _saveAndFree(z.a_, zPos, BLS.mod);
    _free(yPos, BLS.mod);
    _free(xPos, BLS.mod);
    return z;
  }

  public static getFr(): Fr {
    const a = new Fr();
    a.setByCSPRNG();
    return a;
  }

  public static getId(): Id {
    const a = new Id();
    a.setByCSPRNG();
    return a;
  }

  public static getSecretKey(): SecretKey {
    const a = new SecretKey();
    a.setByCSPRNG();
    return a;
  }

  public static deserializeHexStrToFr(s: string): Fr {
    const r = new Fr();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToFp(s: string): Fp {
    const r = new Fp();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToFp2(s: string): Fp2 {
    const r = new Fp2();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToG1(s: string): G1 {
    const r = new G1();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToG2(s: string): G2 {
    const r = new G2();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToGT(s: string): GT {
    const r = new GT();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToId(s: string): Id {
    const r = new Id();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToSecretKey(s: string): SecretKey {
    const r = new SecretKey();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToPublicKey(s: string): PublicKey {
    const r = new PublicKey();
    r.deserializeHexStr(s);
    return r;
  }

  public static deserializeHexStrToSignature(s: string): Signature {
    const r = new Signature();
    r.deserializeHexStr(s);
    return r;
  }

  public static setRandFunc(
    func: <T extends NodeJS.ArrayBufferView>(
      buffer: T,
      offset?: number | undefined,
      size?: number | undefined,
    ) => T,
  ): void {
    getRandomValues = func;
  }

  public static setETHserialization(ETHserialization: boolean): void {
    BLS.mod._mclBn_setETHserialization(ETHserialization ? 1 : 0);
  }

  // mode = IRTF = 5 for Ethereum 2.0 spec
  public static setMapToMode(mode: number): boolean {
    return BLS.mod._mclBn_setMapToMode(mode) === 1;
  }

  public static verifyOrderG1(doVerify: boolean): void {
    BLS.mod._mclBn_verifyOrderG1(doVerify ? 1 : 0);
  }

  public static verifyOrderG2(doVerify: boolean): void {
    BLS.mod._mclBn_verifyOrderG2(doVerify ? 1 : 0);
  }

  public static getBasePointG1(): G1 {
    const x = new G1();
    const xPos = _alloc(x.a_, BLS.mod);
    BLS.mod._mclBnG1_getBasePoint(xPos);
    _saveAndFree(x.a_, xPos, BLS.mod);
    if (x.isZero()) {
      throw new Error("not supported for pairing curves");
    }
    return x;
  }

  private static PublicKeyGeneratorG1: PublicKey | null = null;

  private static PublicKeyGeneratorG2: PublicKey | null = null;

  public static GetGeneratorOfPublicKey(): PublicKey {
    if (ethMode) {
      if (!BLS.PublicKeyGeneratorG1) {
        BLS.PublicKeyGeneratorG1 = this._op0(
          this.mod._blsGetGeneratorOfPublicKey,
          PublicKey,
        );
      }
      return BLS.PublicKeyGeneratorG1;
    } else {
      if (!BLS.PublicKeyGeneratorG2) {
        BLS.PublicKeyGeneratorG2 = this._op0(
          this.mod._blsGetGeneratorOfPublicKey,
          PublicKey,
        );
      }
      return BLS.PublicKeyGeneratorG2;
    }
  }

  public static neg(x: Fr): Fr;
  public static neg(x: Fp): Fp;
  public static neg(x: Fp2): Fp2;
  public static neg(x: G1): G1;
  public static neg(x: G2): G2;
  public static neg(x: GT): GT;
  public static neg(x: Common): Common {
    if (x instanceof Fr) {
      return BLS._op1(BLS.mod._mclBnFr_neg, x, Fr);
    }
    if (x instanceof Fp) {
      return BLS._op1(BLS.mod._mclBnFp_neg, x, Fp);
    }
    if (x instanceof Fp2) {
      return BLS._op1(BLS.mod._mclBnG1_neg, x, Fp2);
    }
    if (x instanceof G1) {
      return BLS._op1(BLS.mod._mclBnG2_neg, x, G1);
    }
    if (x instanceof G2) {
      return BLS._op1(BLS.mod._mclBnG2_neg, x, G2);
    }
    if (x instanceof GT) {
      return BLS._op1(BLS.mod._mclBnGT_neg, x, GT);
    }
    throw new Error("neg:mismatch type");
  }

  public static add(x: Fr, y: Fr): Fr;
  public static add(x: Fp, y: Fp): Fp;
  public static add(x: Fp2, y: Fp2): Fp2;
  public static add(x: G1, y: G1): G1;
  public static add(x: G2, y: G2): G2;
  public static add(x: GT, y: GT): GT;
  public static add(x: Common, y: Common): Common {
    if (x.constructor !== y.constructor) {
      throw new Error("add:mismatch type");
    }

    if (x instanceof Fr) {
      return BLS._op2(BLS.mod._mclBnFr_add, x, y, Fr);
    }
    if (x instanceof Fp) {
      return BLS._op2(BLS.mod._mclBnFp_add, x, y, Fp);
    }
    if (x instanceof Fp2) {
      return BLS._op2(BLS.mod._mclBnFp2_add, x, y, Fp2);
    }
    if (x instanceof G1) {
      return BLS._op2(BLS.mod._mclBnG1_add, x, y, G1);
    }
    if (x instanceof G2) {
      return BLS._op2(BLS.mod._mclBnG2_add, x, y, G2);
    }
    if (x instanceof GT) {
      return BLS._op2(BLS.mod._mclBnGT_add, x, y, GT);
    }
    throw new Error("add:mismatch type");
  }

  public static sub(x: Fr, y: Fr): Fr;
  public static sub(x: Fp, y: Fp): Fp;
  public static sub(x: Fp2, y: Fp2): Fp2;
  public static sub(x: G1, y: G1): G1;
  public static sub(x: G2, y: G2): G2;
  public static sub(x: GT, y: GT): GT;
  public static sub(x: Common, y: Common): Common {
    if (x.constructor !== y.constructor) {
      throw new Error("sub:mismatch type");
    }

    if (x instanceof Fr) {
      return BLS._op2(BLS.mod._mclBnFr_sub, x, y, Fr);
    }
    if (x instanceof Fp) {
      return BLS._op2(BLS.mod._mclBnFp_sub, x, y, Fp);
    }
    if (x instanceof Fp2) {
      return BLS._op2(BLS.mod._mclBnFp2_sub, x, y, Fp2);
    }
    if (x instanceof G1) {
      return BLS._op2(BLS.mod._mclBnG1_sub, x, y, G1);
    }
    if (x instanceof G2) {
      return BLS._op2(BLS.mod._mclBnG2_sub, x, y, G2);
    }
    if (x instanceof GT) {
      return BLS._op2(BLS.mod._mclBnGT_sub, x, y, GT);
    }
    throw new Error("sub:mismatch type");
  }

  /*
		Fr * Fr
		Fp * Fp
		Fp2 * Fp2
		G1 * Fr ; scalar mul
		G2 * Fr ; scalar mul
		GT * GT
	*/
  public static mul(x: Fr, y: Fr): Fr;
  public static mul(x: Fp, y: Fp): Fp;
  public static mul(x: Fp2, y: Fp2): Fp2;
  public static mul(x: G1, y: Fr): G1;
  public static mul(x: G2, y: Fr): G2;
  public static mul(x: GT, y: GT): GT;
  public static mul(x: Common, y: Common): Common {
    if (x instanceof Fr && y instanceof Fr) {
      return BLS._op2(BLS.mod._mclBnFr_mul, x, y, Fr);
    }
    if (x instanceof Fp && y instanceof Fp) {
      return BLS._op2(BLS.mod._mclBnFp_mul, x, y, Fp);
    }
    if (x instanceof Fp2 && y instanceof Fp2) {
      return BLS._op2(BLS.mod._mclBnFp2_mul, x, y, Fp2);
    }
    if (x instanceof G1 && y instanceof Fr) {
      return BLS._op2(BLS.mod._mclBnG1_mul, x, y, G1);
    }
    if (x instanceof G2 && y instanceof Fr) {
      return BLS._op2(BLS.mod._mclBnG2_mul, x, y, G2);
    }
    if (x instanceof GT && y instanceof GT) {
      return BLS._op2(BLS.mod._mclBnGT_mul, x, y, GT);
    }
    throw new Error("mul:mismatch type");
  }

  /*
		sum G1 * Fr ; scalar mul
		sum G2 * Fr ; scalar mul
	*/
  public static mulVec(xVec: G1[], yVec: Fr[]): G1;
  public static mulVec(xVec: G2[], yVec: Fr[]): G2;
  public static mulVec(xVec: Common[], yVec: Common[]): Common {
    if (xVec.length === 0) {
      throw new Error("mulVec:zero array");
    }
    if (xVec[0] instanceof G1 && yVec[0] instanceof Fr) {
      return _mulVec(BLS.mod._mclBnG1_mulVec, xVec, yVec, G1, BLS.mod);
    }
    if (xVec[0] instanceof G2 && yVec[0] instanceof Fr) {
      return _mulVec(BLS.mod._mclBnG2_mulVec, xVec, yVec, G2, BLS.mod);
    }
    throw new Error("mulVec:mismatch type");
  }

  public static div(x: Fr, y: Fr): Fr;
  public static div(x: Fp, y: Fp): Fp;
  public static div(x: Fp2, y: Fp2): Fp2;
  public static div(x: GT, y: GT): GT;
  public static div(x: Common, y: Common): Common {
    if (x.constructor !== y.constructor) {
      throw new Error("div:mismatch type");
    }
    if (x instanceof Fr) {
      return BLS._op2(BLS.mod._mclBnFr_div, x, y, Fr);
    }
    if (x instanceof Fp) {
      return BLS._op2(BLS.mod._mclBnFp_div, x, y, Fp);
    }
    if (x instanceof Fp2) {
      return BLS._op2(BLS.mod._mclBnFp2_div, x, y, Fp2);
    }
    if (x instanceof GT) {
      return BLS._op2(BLS.mod._mclBnGT_div, x, y, GT);
    }
    throw new Error("div:mismatch type");
  }

  public static inv(x: Fr): Fr;
  public static inv(x: Fp): Fp;
  public static inv(x: Fp2): Fp2;
  public static inv(x: GT): GT;
  public static inv(x: Common): Common {
    if (x instanceof Fr) {
      return BLS._op1(BLS.mod._mclBnFr_inv, x, Fr);
    }
    if (x instanceof Fp) {
      return BLS._op1(BLS.mod._mclBnFp_inv, x, Fp);
    }
    if (x instanceof Fp2) {
      return BLS._op1(BLS.mod._mclBnFp2_inv, x, Fp2);
    }
    if (x instanceof GT) {
      return BLS._op1(BLS.mod._mclBnGT_inv, x, GT);
    }
    throw new Error("inv:mismatch type");
  }

  public static sqr(x: Fr): Fr;
  public static sqr(x: Fp): Fp;
  public static sqr(x: Fp2): Fp2;
  public static sqr(x: GT): GT;
  public static sqr(x: Common): Common {
    if (x instanceof Fr) {
      return BLS._op1(BLS.mod._mclBnFr_sqr, x, Fr);
    }
    if (x instanceof Fp) {
      return BLS._op1(BLS.mod._mclBnFp_sqr, x, Fp);
    }
    if (x instanceof Fp2) {
      return BLS._op1(BLS.mod._mclBnFp2_sqr, x, Fp2);
    }
    if (x instanceof GT) {
      return BLS._op1(BLS.mod._mclBnGT_sqr, x, GT);
    }
    throw new Error("inv:mismatch type");
  }

  public static dbl(x: G1): G1;
  public static dbl(x: G2): G2;
  public static dbl(x: Common): Common {
    if (x instanceof G1) {
      return BLS._op1(BLS.mod._mclBnG1_dbl, x, G1);
    }
    if (x instanceof G2) {
      return BLS._op1(BLS.mod._mclBnG2_dbl, x, G1);
    }
    throw new Error("dbl:bad type");
  }

  public static normalize(x: G1): G1;
  public static normalize(x: G2): G2;
  public static normalize(x: Common): Common {
    if (x instanceof G1) {
      return BLS._op1(BLS.mod._mclBnG1_normalize, x, G1);
    }
    if (x instanceof G2) {
      return BLS._op1(BLS.mod._mclBnG2_normalize, x, G1);
    }
    throw new Error("normalize:bad type");
  }

  public static hashToFr(s: string | Uint8Array): Fr {
    const x = new Fr();
    x.setHashOf(s);
    return x;
  }

  public static hashToFp(s: string | Uint8Array): Fp {
    const x = new Fp();
    x.setHashOf(s);
    return x;
  }

  public static hashAndMapToG1(s: string | Uint8Array): G1 {
    const x = new G1();
    x.setHashOf(s);
    return x;
  }

  public static hashAndMapToG2(s: string | Uint8Array): G2 {
    const x = new G2();
    x.setHashOf(s);
    return x;
  }

  // pow(GT x, Fr y)
  public static pow(x: GT, y: Fr): GT {
    return BLS._op2(BLS.mod._mclBnGT_pow, x, y, GT);
  }

  // pairing(G1 P, G2 Q)
  public static pairing(P: G1, Q: G2): GT {
    return BLS._op2(BLS.mod._mclBn_pairing, P, Q, GT);
  }

  // millerLoop(G1 P, G2 Q)
  public static millerLoop(P: G1, Q: G2): GT {
    return BLS._op2(BLS.mod._mclBn_millerLoop, P, Q, GT);
  }

  public static precomputedMillerLoop(P: G1, Qcoeff: PrecomputedG2): GT {
    if (!Qcoeff.p) {
      throw new Error("Qcoeff is not initialized!");
    }
    const e = new GT();
    const PPos = _allocAndCopy(P.a_, BLS.mod);
    const ePos = _alloc(e.a_, BLS.mod);
    BLS.mod._mclBn_precomputedMillerLoop(ePos, PPos, Qcoeff.p);
    _saveAndFree(e.a_, ePos, BLS.mod);
    _free(PPos, BLS.mod);
    return e;
  }

  // millerLoop(P1, Q1coeff) * millerLoop(P2, Q2coeff)
  public static precomputedMillerLoop2(
    P1: G1,
    Q1coeff: PrecomputedG2,
    P2: G1,
    Q2coeff: PrecomputedG2,
  ): GT {
    if (!Q1coeff.p || !Q2coeff.p) {
      throw new Error("Coeffs are not initialized!");
    }
    const e = new GT();
    const P1Pos = _allocAndCopy(P1.a_, BLS.mod);
    const P2Pos = _allocAndCopy(P2.a_, BLS.mod);
    const ePos = _alloc(e.a_, BLS.mod);
    BLS.mod._mclBn_precomputedMillerLoop2(
      ePos,
      P1Pos,
      Q1coeff.p,
      P2Pos,
      Q2coeff.p,
    );
    _saveAndFree(e.a_, ePos, BLS.mod);
    _free(P1Pos, BLS.mod);
    _free(P2Pos, BLS.mod);
    return e;
  }

  // millerLoop(P1, Q1) * millerLoop(P2, Q2coeff)
  public static precomputedMillerLoop2mixed(
    P1: G1,
    Q1: G2,
    P2: G1,
    Q2coeff: PrecomputedG2,
  ): GT {
    if (!Q2coeff.p) {
      throw new Error("Q2coeff is not initialized!");
    }
    const e = new GT();
    const P1Pos = _allocAndCopy(P1.a_, BLS.mod);
    const Q1Pos = _allocAndCopy(Q1.a_, BLS.mod);
    const P2Pos = _allocAndCopy(P2.a_, BLS.mod);
    const ePos = _alloc(e.a_, BLS.mod);
    BLS.mod._mclBn_precomputedMillerLoop2mixed(
      ePos,
      P1Pos,
      Q1Pos,
      P2Pos,
      Q2coeff.p,
    );
    _saveAndFree(e.a_, ePos, BLS.mod);
    _free(P1Pos, BLS.mod);
    _free(Q1Pos, BLS.mod);
    _free(P2Pos, BLS.mod);
    return e;
  }

  public static finalExp = (x: GT): GT => {
    return BLS._op1(BLS.mod._mclBn_finalExp, x, GT);
  };

  public static isDefault(): boolean {
    return !ethMode;
  }

  private static isInitialized = false;

  public static async init(isETH: boolean): Promise<void> {
    if (BLS.isInitialized) {
      return;
    }

    await _init(isETH);

    BLS.isInitialized = true;
  }
}
