import type { HexString } from "../types/utils.types";
import type { EncryptedData, KeyPair } from "./hiver.types";

import { Hasher } from "./hasher";
import { Randomer } from "./randomer";
import { Readable } from "node:stream";
import { AesCrypter } from "./aes-crypter";
import { PassThrough } from "stream";
import { timingSafeEqual } from "node:crypto";
import { BLS, Id, SecretKey, PublicKey, Signature, Fr } from "./bls-helper";

const KEY_LENGTH_IN_BYTE = 32;
const IV_LENGTH_IN_BYTE = 16;

class HiverTypeGuards {
  public static sigVecIsHexString(
    members: HexString[] | Buffer[] | Uint8Array[] | Signature[] | unknown[],
  ): members is HexString[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => typeof item !== "string")) {
      return false;
    }
    return true;
  }

  public static sigVecIsBuffer(
    members: HexString[] | Buffer[] | Uint8Array[] | Signature[] | unknown[],
  ): members is Buffer[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item instanceof Buffer))) {
      return false;
    }
    return true;
  }

  public static sigVecIsUint8Array(
    members: HexString[] | Buffer[] | Uint8Array[] | Signature[] | unknown[],
  ): members is Uint8Array[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item instanceof Uint8Array))) {
      return false;
    }
    return true;
  }

  public static sigVecIsNative(
    members: HexString[] | Buffer[] | Uint8Array[] | Signature[] | unknown[],
  ): members is Signature[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item instanceof Signature))) {
      return false;
    }
    return true;
  }

  public static idVecIsHexString(
    members: HexString[] | Buffer[] | Uint8Array[] | Id[] | unknown[],
  ): members is HexString[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => typeof item !== "string")) {
      return false;
    }
    return true;
  }

  public static idVecIsBuffer(
    members: HexString[] | Buffer[] | Uint8Array[] | Id[] | unknown[],
  ): members is Buffer[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item instanceof Buffer))) {
      return false;
    }
    return true;
  }

  public static idVecIsUint8Array(
    members: HexString[] | Buffer[] | Uint8Array[] | Id[] | unknown[],
  ): members is Uint8Array[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item instanceof Uint8Array))) {
      return false;
    }
    return true;
  }

  public static idVecIsNative(
    members: HexString[] | Buffer[] | Uint8Array[] | Id[] | unknown[],
  ): members is Id[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item instanceof Id))) {
      return false;
    }
    return true;
  }
}

export class Hiver {
  private static isInitialized = false;

  public static async init(): Promise<void> {
    if (Hiver.isInitialized) {
      return;
    }

    await BLS.init(false);

    Hiver.isInitialized = true;
  }

  public static generateKeyPairHex(): KeyPair<HexString, HexString> {
    const secKey = new SecretKey();
    secKey.setByCSPRNG();
    return {
      secretKey: secKey.serializeToHexStr(),
      publicKey: secKey.getPublicKey().serializeToHexStr(),
    };
  }

  public static generateKeyPairBuffer(): KeyPair<Buffer, Buffer> {
    const secKey = new SecretKey();
    secKey.setByCSPRNG();
    return {
      secretKey: Buffer.from(secKey.serialize()),
      publicKey: Buffer.from(secKey.getPublicKey().serialize()),
    };
  }

  public static generateKeyPairUint8Array(): KeyPair<Uint8Array, Uint8Array> {
    const secKey = new SecretKey();
    secKey.setByCSPRNG();
    return {
      secretKey: secKey.serialize(),
      publicKey: secKey.getPublicKey().serialize(),
    };
  }

  public static generateKeyPair(): KeyPair<SecretKey, PublicKey> {
    const secKey = new SecretKey();
    secKey.setByCSPRNG();
    return {
      secretKey: secKey,
      publicKey: secKey.getPublicKey(),
    };
  }

  public static generateId(): Id {
    const a = new Id();
    a.setByCSPRNG();
    return a;
  }

  public static generateSecretKey(): SecretKey {
    const a = new SecretKey();
    a.setByCSPRNG();
    return a;
  }

  public static generatePublicKey(secretKey: HexString): PublicKey;
  public static generatePublicKey(secretKey: Buffer): PublicKey;
  public static generatePublicKey(secretKey: Uint8Array): PublicKey;
  public static generatePublicKey(secretKey: SecretKey): PublicKey;
  public static generatePublicKey(secretKey: unknown): PublicKey {
    if (typeof secretKey === "string") {
      return BLS.deserializeHexStrToSecretKey(secretKey).getPublicKey();
    }
    if (secretKey instanceof Buffer) {
      const temp = new SecretKey();
      temp.deserialize(new Uint8Array(secretKey));
      return temp.getPublicKey();
    }
    if (secretKey instanceof Uint8Array) {
      const temp = new SecretKey();
      temp.deserialize(secretKey);
      return temp.getPublicKey();
    }
    if (secretKey instanceof SecretKey) {
      return secretKey.getPublicKey();
    }
    throw new Error("generatePublicKey:mismatch type");
  }

  public static toHex(data: Id): HexString;
  public static toHex(data: SecretKey): HexString;
  public static toHex(data: PublicKey): HexString;
  public static toHex(data: Signature): HexString;
  public static toHex(data: unknown): unknown {
    if (
      data instanceof Id ||
      data instanceof SecretKey ||
      data instanceof PublicKey ||
      data instanceof Signature
    ) {
      return data.serializeToHexStr();
    }
    throw new Error("toHex:mismatch type");
  }

  public static toBuffer(data: Id): Buffer;
  public static toBuffer(data: SecretKey): Buffer;
  public static toBuffer(data: PublicKey): Buffer;
  public static toBuffer(data: Signature): Buffer;
  public static toBuffer(data: unknown): Buffer {
    if (
      data instanceof Id ||
      data instanceof SecretKey ||
      data instanceof PublicKey ||
      data instanceof Signature
    ) {
      return Buffer.from(data.serialize());
    }
    throw new Error("toBuffer:mismatch type");
  }

  public static toUint8Array(data: Id): Uint8Array;
  public static toUint8Array(data: SecretKey): Uint8Array;
  public static toUint8Array(data: PublicKey): Uint8Array;
  public static toUint8Array(data: Signature): Uint8Array;
  public static toUint8Array(data: unknown): Uint8Array {
    if (
      data instanceof Id ||
      data instanceof SecretKey ||
      data instanceof PublicKey ||
      data instanceof Signature
    ) {
      return data.serialize();
    }
    throw new Error("toUint8Array:mismatch type");
  }

  public static toFr(data: HexString): Fr;
  public static toFr(data: Buffer): Fr;
  public static toFr(data: Uint8Array): Fr;
  public static toFr(data: unknown): Fr {
    if (typeof data === "string") {
      const a = new Fr();
      a.deserializeHexStr(data);
      return a;
    }
    if (data instanceof Buffer) {
      const a = new Fr();
      a.deserialize(new Uint8Array(data));
      return a;
    }
    if (data instanceof Uint8Array) {
      const a = new Fr();
      a.deserialize(data);
      return a;
    }
    throw new Error("toFr:mismatch type");
  }

  public static toId(data: HexString): Id;
  public static toId(data: Buffer): Id;
  public static toId(data: Uint8Array): Id;
  public static toId(data: unknown): Id {
    if (typeof data === "string") {
      const a = new Id();
      a.deserializeHexStr(data);
      return a;
    }
    if (data instanceof Buffer) {
      const a = new Id();
      a.deserialize(new Uint8Array(data));
      return a;
    }
    if (data instanceof Uint8Array) {
      const a = new Id();
      a.deserialize(data);
      return a;
    }
    throw new Error("toId:mismatch type");
  }

  public static toSecretKey(data: HexString): SecretKey;
  public static toSecretKey(data: Buffer): SecretKey;
  public static toSecretKey(data: Uint8Array): SecretKey;
  public static toSecretKey(data: unknown): SecretKey {
    if (typeof data === "string") {
      const a = new SecretKey();
      a.deserializeHexStr(data);
      return a;
    }
    if (data instanceof Buffer) {
      const a = new SecretKey();
      a.deserialize(new Uint8Array(data));
      return a;
    }
    if (data instanceof Uint8Array) {
      const a = new SecretKey();
      a.deserialize(data);
      return a;
    }
    throw new Error("toId:mismatch type");
  }

  public static toPublicKey(data: HexString): PublicKey;
  public static toPublicKey(data: Buffer): PublicKey;
  public static toPublicKey(data: Uint8Array): PublicKey;
  public static toPublicKey(data: unknown): PublicKey {
    if (typeof data === "string") {
      const a = new PublicKey();
      a.deserializeHexStr(data);
      return a;
    }
    if (data instanceof Buffer) {
      const a = new PublicKey();
      a.deserialize(new Uint8Array(data));
      return a;
    }
    if (data instanceof Uint8Array) {
      const a = new PublicKey();
      a.deserialize(data);
      return a;
    }
    throw new Error("toId:mismatch type");
  }

  public static toSignature(data: HexString): Signature;
  public static toSignature(data: Buffer): Signature;
  public static toSignature(data: Uint8Array): Signature;
  public static toSignature(data: unknown): Signature {
    if (typeof data === "string") {
      const a = new Signature();
      a.deserializeHexStr(data);
      return a;
    }
    if (data instanceof Buffer) {
      const a = new Signature();
      a.deserialize(new Uint8Array(data));
      return a;
    }
    if (data instanceof Uint8Array) {
      const a = new Signature();
      a.deserialize(data);
      return a;
    }
    throw new Error("toId:mismatch type");
  }

  public static signBuffer(data: Buffer, secretKey: HexString): Signature;
  public static signBuffer(data: Buffer, secretKey: Buffer): Signature;
  public static signBuffer(data: Buffer, secretKey: Uint8Array): Signature;
  public static signBuffer(data: Buffer, secretKey: SecretKey): Signature;
  public static signBuffer(data: Buffer, secretKey: unknown): Signature {
    if (typeof secretKey === "string") {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserializeHexStr(secretKey);
      const hash = Hasher.sha512Buffer(data);
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Buffer) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(new Uint8Array(secretKey));
      const hash = Hasher.sha512Buffer(data);
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Uint8Array) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(secretKey);
      const hash = Hasher.sha512Buffer(data);
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof SecretKey) {
      const hash = Hasher.sha512Buffer(data);
      return secretKey.sign(new Uint8Array(hash));
    }
    throw new Error("signBuffer:mismatch type");
  }

  public static signHex(data: HexString, secretKey: HexString): Signature;
  public static signHex(data: HexString, secretKey: Buffer): Signature;
  public static signHex(data: HexString, secretKey: Uint8Array): Signature;
  public static signHex(data: HexString, secretKey: SecretKey): Signature;
  public static signHex(data: HexString, secretKey: unknown): Signature {
    if (typeof secretKey === "string") {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserializeHexStr(secretKey);
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Buffer) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(new Uint8Array(secretKey));
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Uint8Array) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(secretKey);
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof SecretKey) {
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return secretKey.sign(new Uint8Array(hash));
    }
    throw new Error("signHex:mismatch type");
  }

  public static sign(
    data: object,
    dataEncoding: BufferEncoding,
    secretKey: HexString,
  ): Signature;
  public static sign(
    data: object,
    dataEncoding: BufferEncoding,
    secretKey: Uint8Array,
  ): Signature;
  public static sign(
    data: object,
    dataEncoding: BufferEncoding,
    secretKey: Buffer,
  ): Signature;
  public static sign(
    data: object,
    dataEncoding: BufferEncoding,
    secretKey: SecretKey,
  ): Signature;
  public static sign(
    data: string,
    dataEncoding: BufferEncoding,
    secretKey: HexString,
  ): Signature;
  public static sign(
    data: string,
    dataEncoding: BufferEncoding,
    secretKey: Buffer,
  ): Signature;
  public static sign(
    data: string,
    dataEncoding: BufferEncoding,
    secretKey: Uint8Array,
  ): Signature;
  public static sign(
    data: string,
    dataEncoding: BufferEncoding,
    secretKey: SecretKey,
  ): Signature;
  public static sign(
    data: unknown,
    dataEncoding: BufferEncoding,
    secretKey: unknown,
  ): Signature {
    const dataStr =
      typeof data !== "string" ? Hasher.stringify(data as object) : data;

    if (typeof secretKey === "string") {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserializeHexStr(secretKey);
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Buffer) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(new Uint8Array(secretKey));
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Uint8Array) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(secretKey);
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof SecretKey) {
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return secretKey.sign(new Uint8Array(hash));
    }
    throw new Error("sign:mismatch type");
  }

  public static signHashBuffer(hash: Buffer, secretKey: HexString): Signature;
  public static signHashBuffer(hash: Buffer, secretKey: Buffer): Signature;
  public static signHashBuffer(hash: Buffer, secretKey: Uint8Array): Signature;
  public static signHashBuffer(hash: Buffer, secretKey: SecretKey): Signature;
  public static signHashBuffer(hash: Buffer, secretKey: unknown): Signature {
    if (typeof secretKey === "string") {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserializeHexStr(secretKey);
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Buffer) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(new Uint8Array(secretKey));
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof Uint8Array) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(secretKey);
      return secretKeyTemp.sign(new Uint8Array(hash));
    }
    if (secretKey instanceof SecretKey) {
      return secretKey.sign(new Uint8Array(hash));
    }
    throw new Error("signHashBuffer:mismatch type");
  }

  public static signHashHex(hash: HexString, secretKey: HexString): Signature;
  public static signHashHex(hash: HexString, secretKey: Buffer): Signature;
  public static signHashHex(hash: HexString, secretKey: Uint8Array): Signature;
  public static signHashHex(hash: HexString, secretKey: SecretKey): Signature;
  public static signHashHex(hash: HexString, secretKey: unknown): Signature {
    if (typeof secretKey === "string") {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserializeHexStr(secretKey);
      return secretKeyTemp.sign(new Uint8Array(Buffer.from(hash, "hex")));
    }
    if (secretKey instanceof Buffer) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(new Uint8Array(secretKey));
      return secretKeyTemp.sign(new Uint8Array(Buffer.from(hash, "hex")));
    }
    if (secretKey instanceof Uint8Array) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(secretKey);
      return secretKeyTemp.sign(new Uint8Array(Buffer.from(hash, "hex")));
    }
    if (secretKey instanceof SecretKey) {
      return secretKey.sign(new Uint8Array(Buffer.from(hash, "hex")));
    }
    throw new Error("signHashHex:mismatch type");
  }

  public static signHash(
    hash: string,
    hashEncoding: BufferEncoding,
    secretKey: HexString,
  ): Signature;
  public static signHash(
    hash: string,
    hashEncoding: BufferEncoding,
    secretKey: Buffer,
  ): Signature;
  public static signHash(
    hash: string,
    hashEncoding: BufferEncoding,
    secretKey: Uint8Array,
  ): Signature;
  public static signHash(
    hash: string,
    hashEncoding: BufferEncoding,
    secretKey: SecretKey,
  ): Signature;
  public static signHash(
    hash: string,
    hashEncoding: BufferEncoding,
    secretKey: unknown,
  ): Signature {
    if (typeof secretKey === "string") {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserializeHexStr(secretKey);
      return secretKeyTemp.sign(
        new Uint8Array(Buffer.from(hash, hashEncoding)),
      );
    }
    if (secretKey instanceof Buffer) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(new Uint8Array(secretKey));
      return secretKeyTemp.sign(
        new Uint8Array(Buffer.from(hash, hashEncoding)),
      );
    }
    if (secretKey instanceof Uint8Array) {
      const secretKeyTemp = new SecretKey();
      secretKeyTemp.deserialize(secretKey);
      return secretKeyTemp.sign(
        new Uint8Array(Buffer.from(hash, hashEncoding)),
      );
    }
    if (secretKey instanceof SecretKey) {
      return secretKey.sign(new Uint8Array(Buffer.from(hash, hashEncoding)));
    }
    throw new Error("signHash:mismatch type");
  }

  public static verifyBuffer(
    data: Buffer,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verifyBuffer(
    data: Buffer,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verifyBuffer(
    data: Buffer,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verifyBuffer(
    data: Buffer,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verifyBuffer(
    data: Buffer,
    publicKey: unknown,
    signature: unknown,
  ): boolean {
    if (typeof publicKey === "string" && typeof signature === "string") {
      const publicKeyTemp = BLS.deserializeHexStrToPublicKey(publicKey);
      const signatureTemp = BLS.deserializeHexStrToSignature(signature);
      const hash = Hasher.sha512Buffer(data);
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Buffer && signature instanceof Buffer) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(new Uint8Array(publicKey));
      const signatureTemp = new Signature();
      signatureTemp.deserialize(new Uint8Array(signature));
      const hash = Hasher.sha512Buffer(data);
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Uint8Array && signature instanceof Uint8Array) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(publicKey);
      const signatureTemp = new Signature();
      signatureTemp.deserialize(signature);
      const hash = Hasher.sha512Buffer(data);
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof PublicKey && signature instanceof Signature) {
      const hash = Hasher.sha512Buffer(data);
      return publicKey.verify(signature, new Uint8Array(hash));
    }
    throw new Error("verify:mismatch type");
  }

  public static verifyHex(
    data: HexString,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verifyHex(
    data: HexString,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verifyHex(
    data: HexString,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verifyHex(
    data: HexString,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verifyHex(
    data: HexString,
    publicKey: unknown,
    signature: unknown,
  ): boolean {
    if (typeof publicKey === "string" && typeof signature === "string") {
      const publicKeyTemp = BLS.deserializeHexStrToPublicKey(publicKey);
      const signatureTemp = BLS.deserializeHexStrToSignature(signature);
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Buffer && signature instanceof Buffer) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(new Uint8Array(publicKey));
      const signatureTemp = new Signature();
      signatureTemp.deserialize(new Uint8Array(signature));
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Uint8Array && signature instanceof Uint8Array) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(publicKey);
      const signatureTemp = new Signature();
      signatureTemp.deserialize(signature);
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof PublicKey && signature instanceof Signature) {
      const hash = Hasher.sha512Buffer(Buffer.from(data, "hex"));
      return publicKey.verify(signature, new Uint8Array(hash));
    }
    throw new Error("verify:mismatch type");
  }

  public static verify(
    data: Record<string, unknown>,
    dataEncoding: BufferEncoding,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verify(
    data: Record<string, unknown>,
    dataEncoding: BufferEncoding,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verify(
    data: Record<string, unknown>,
    dataEncoding: BufferEncoding,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verify(
    data: Record<string, unknown>,
    dataEncoding: BufferEncoding,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verify(
    data: string,
    dataEncoding: BufferEncoding,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verify(
    data: string,
    dataEncoding: BufferEncoding,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verify(
    data: string,
    dataEncoding: BufferEncoding,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verify(
    data: string,
    dataEncoding: BufferEncoding,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verify(
    data: unknown,
    dataEncoding: BufferEncoding,
    publicKey: unknown,
    signature: unknown,
  ): boolean {
    const dataStr =
      typeof data !== "string" ? Hasher.stringify(data as object) : data;

    if (typeof publicKey === "string" && typeof signature === "string") {
      const publicKeyTemp = BLS.deserializeHexStrToPublicKey(publicKey);
      const signatureTemp = BLS.deserializeHexStrToSignature(signature);
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Buffer && signature instanceof Buffer) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(new Uint8Array(publicKey));
      const signatureTemp = new Signature();
      signatureTemp.deserialize(new Uint8Array(signature));
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Uint8Array && signature instanceof Uint8Array) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(publicKey);
      const signatureTemp = new Signature();
      signatureTemp.deserialize(signature);
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof PublicKey && signature instanceof Signature) {
      const hash = Hasher.sha512Buffer(Buffer.from(dataStr, dataEncoding));
      return publicKey.verify(signature, new Uint8Array(hash));
    }
    throw new Error("verify:mismatch type");
  }

  public static verifyHashBuffer(
    hash: Buffer,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verifyHashBuffer(
    hash: Buffer,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verifyHashBuffer(
    hash: Buffer,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verifyHashBuffer(
    hash: Buffer,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verifyHashBuffer(
    hash: Buffer,
    publicKey: unknown,
    signature: unknown,
  ): boolean {
    if (typeof publicKey === "string" && typeof signature === "string") {
      const publicKeyTemp = BLS.deserializeHexStrToPublicKey(publicKey);
      const signatureTemp = BLS.deserializeHexStrToSignature(signature);
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Buffer && signature instanceof Buffer) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(new Uint8Array(publicKey));
      const signatureTemp = new Signature();
      signatureTemp.deserialize(new Uint8Array(signature));
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof Uint8Array && signature instanceof Uint8Array) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(publicKey);
      const signatureTemp = new Signature();
      signatureTemp.deserialize(signature);
      return publicKeyTemp.verify(signatureTemp, new Uint8Array(hash));
    }
    if (publicKey instanceof PublicKey && signature instanceof Signature) {
      return publicKey.verify(signature, new Uint8Array(hash));
    }
    throw new Error("verify:mismatch type");
  }

  public static verifyHashHex(
    hash: HexString,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verifyHashHex(
    hash: HexString,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verifyHashHex(
    hash: HexString,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verifyHashHex(
    hash: HexString,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verifyHashHex(
    hash: HexString,
    publicKey: unknown,
    signature: unknown,
  ): boolean {
    if (typeof publicKey === "string" && typeof signature === "string") {
      const publicKeyTemp = BLS.deserializeHexStrToPublicKey(publicKey);
      const signatureTemp = BLS.deserializeHexStrToSignature(signature);
      return publicKeyTemp.verify(
        signatureTemp,
        new Uint8Array(Buffer.from(hash, "hex")),
      );
    }
    if (publicKey instanceof Buffer && signature instanceof Buffer) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(new Uint8Array(publicKey));
      const signatureTemp = new Signature();
      signatureTemp.deserialize(new Uint8Array(signature));
      return publicKeyTemp.verify(
        signatureTemp,
        new Uint8Array(Buffer.from(hash, "hex")),
      );
    }
    if (publicKey instanceof Uint8Array && signature instanceof Uint8Array) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(publicKey);
      const signatureTemp = new Signature();
      signatureTemp.deserialize(signature);
      return publicKeyTemp.verify(
        signatureTemp,
        new Uint8Array(Buffer.from(hash, "hex")),
      );
    }
    if (publicKey instanceof PublicKey && signature instanceof Signature) {
      return publicKey.verify(
        signature,
        new Uint8Array(Buffer.from(hash, "hex")),
      );
    }
    throw new Error("verify:mismatch type");
  }

  public static verifyHash(
    hash: string,
    dataEncoding: BufferEncoding,
    publicKey: HexString,
    signature: HexString,
  ): boolean;
  public static verifyHash(
    hash: string,
    dataEncoding: BufferEncoding,
    publicKey: Buffer,
    signature: Buffer,
  ): boolean;
  public static verifyHash(
    hash: string,
    dataEncoding: BufferEncoding,
    publicKey: Uint8Array,
    signature: Uint8Array,
  ): boolean;
  public static verifyHash(
    hash: string,
    dataEncoding: BufferEncoding,
    publicKey: PublicKey,
    signature: Signature,
  ): boolean;
  public static verifyHash(
    hash: string,
    dataEncoding: BufferEncoding,
    publicKey: unknown,
    signature: unknown,
  ): boolean {
    if (typeof publicKey === "string" && typeof signature === "string") {
      const publicKeyTemp = BLS.deserializeHexStrToPublicKey(publicKey);
      const signatureTemp = BLS.deserializeHexStrToSignature(signature);
      return publicKeyTemp.verify(
        signatureTemp,
        new Uint8Array(Buffer.from(hash, dataEncoding)),
      );
    }
    if (publicKey instanceof Buffer && signature instanceof Buffer) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(new Uint8Array(publicKey));
      const signatureTemp = new Signature();
      signatureTemp.deserialize(new Uint8Array(signature));
      return publicKeyTemp.verify(
        signatureTemp,
        new Uint8Array(Buffer.from(hash, dataEncoding)),
      );
    }
    if (publicKey instanceof Uint8Array && signature instanceof Uint8Array) {
      const publicKeyTemp = new PublicKey();
      publicKeyTemp.deserialize(publicKey);
      const signatureTemp = new Signature();
      signatureTemp.deserialize(signature);
      return publicKeyTemp.verify(
        signatureTemp,
        new Uint8Array(Buffer.from(hash, dataEncoding)),
      );
    }
    if (publicKey instanceof PublicKey && signature instanceof Signature) {
      return publicKey.verify(
        signature,
        new Uint8Array(Buffer.from(hash, dataEncoding)),
      );
    }
    throw new Error("verify:mismatch type");
  }

  public static recoverSign(sigVec: HexString[], idVec: HexString[]): Signature;
  public static recoverSign(sigVec: Buffer[], idVec: Buffer[]): Signature;
  public static recoverSign(
    sigVec: Uint8Array[],
    idVec: Uint8Array[],
  ): Signature;
  public static recoverSign(sigVec: Signature[], idVec: Id[]): Signature;
  public static recoverSign(sigVec: unknown[], idVec: unknown[]): Signature {
    if (
      HiverTypeGuards.sigVecIsHexString(sigVec) &&
      HiverTypeGuards.idVecIsHexString(idVec)
    ) {
      const a = new Signature();
      const sigVecTemp = sigVec.map((item) =>
        BLS.deserializeHexStrToSignature(item),
      );
      const idVecTemp = sigVec.map((item) => BLS.deserializeHexStrToId(item));
      a.recover(sigVecTemp, idVecTemp);
      return a;
    }
    if (
      HiverTypeGuards.sigVecIsBuffer(sigVec) &&
      HiverTypeGuards.idVecIsBuffer(idVec)
    ) {
      const a = new Signature();
      const sigVecTemp = sigVec.map((item) => {
        const sig = new Signature();
        sig.deserialize(new Uint8Array(item));
        return sig;
      });
      const idVecTemp = sigVec.map((item) => {
        const id = new Id();
        id.deserialize(new Uint8Array(item));
        return id;
      });
      a.recover(sigVecTemp, idVecTemp);
      return a;
    }
    if (
      HiverTypeGuards.sigVecIsUint8Array(sigVec) &&
      HiverTypeGuards.idVecIsUint8Array(idVec)
    ) {
      const a = new Signature();
      const sigVecTemp = sigVec.map((item) => {
        const sig = new Signature();
        sig.deserialize(item);
        return sig;
      });
      const idVecTemp = sigVec.map((item) => {
        const id = new Id();
        id.deserialize(item);
        return id;
      });
      a.recover(sigVecTemp, idVecTemp);
      return a;
    }
    if (
      HiverTypeGuards.sigVecIsNative(sigVec) &&
      HiverTypeGuards.idVecIsNative(idVec)
    ) {
      const a = new Signature();
      a.recover(sigVec, idVec);
      return a;
    }
    throw new Error("recoverSign:mismatch type");
  }

  public static encryptECIESBuffer(
    plainDataBuffer: Buffer,
    publicKeyBuffer: Buffer,
  ): EncryptedData<Buffer> {
    const ephemeralKey = Hiver.generateKeyPair();
    const publicKey = new PublicKey();
    publicKey.deserialize(new Uint8Array(publicKeyBuffer));
    const px = ephemeralKey.secretKey.getDHKeyExchange(publicKey);
    const hash = Hasher.sha512Buffer(Buffer.from(px.serialize()));
    // replace Buffer.slice
    const encryptionKey = Buffer.from(hash.subarray(0, KEY_LENGTH_IN_BYTE));
    const macKey = Buffer.from(hash.subarray(KEY_LENGTH_IN_BYTE));
    const iv = Randomer.randomBytes(IV_LENGTH_IN_BYTE, true);
    const cipherData = AesCrypter.encryptAES256CbcBuffer(
      plainDataBuffer,
      iv,
      encryptionKey,
    );
    const dataToMac = Buffer.concat([
      iv,
      Buffer.from(ephemeralKey.publicKey.serialize()),
      cipherData,
    ]);
    const mac = Hasher.hmacSha512Buffer(macKey, dataToMac);

    return {
      iv: iv,
      ephemeralPublicKey: Buffer.from(ephemeralKey.publicKey.serialize()),
      cipherData: cipherData,
      mac: mac,
    };
  }

  public static decryptECIESBuffer(
    encryptedData: EncryptedData<Buffer>,
    privateKeyBuffer: Buffer,
  ): Buffer {
    const secretKey = new SecretKey();
    secretKey.deserialize(new Uint8Array(privateKeyBuffer));
    const publicKey = new PublicKey();
    publicKey.deserialize(new Uint8Array(encryptedData.ephemeralPublicKey));
    const px = secretKey.getDHKeyExchange(publicKey);
    const hash = Hasher.sha512Buffer(Buffer.from(px.serialize()));
    const encryptionKey = Buffer.from(hash.subarray(0, KEY_LENGTH_IN_BYTE));
    const macKey = Buffer.from(hash.subarray(KEY_LENGTH_IN_BYTE));
    const dataToMac = Buffer.concat([
      encryptedData.iv,
      encryptedData.ephemeralPublicKey,
      encryptedData.cipherData,
    ]);
    const realMac = Hasher.hmacSha512Buffer(macKey, dataToMac);

    if (!timingSafeEqual(encryptedData.mac, realMac)) {
      throw new Error("BadMAC");
    }

    return AesCrypter.decryptAES256CbcBuffer(
      encryptedData.cipherData,
      encryptedData.iv,
      encryptionKey,
    );
  }

  public static encryptECIESStream(
    plainDataStream: Readable,
    publicKeyBuffer: Buffer,
  ): EncryptedData<Buffer, Readable> {
    const ephemeralKey = Hiver.generateKeyPair();
    const publicKey = new PublicKey();
    publicKey.deserialize(new Uint8Array(publicKeyBuffer));
    const px = ephemeralKey.secretKey.getDHKeyExchange(publicKey);
    const hash = Hasher.sha512Buffer(Buffer.from(px.serialize()));
    const encryptionKey = Buffer.from(hash.subarray(0, KEY_LENGTH_IN_BYTE));
    const macKey = Buffer.from(hash.subarray(KEY_LENGTH_IN_BYTE));
    const iv = Randomer.randomBytes(IV_LENGTH_IN_BYTE, true);

    const outDataStream = new PassThrough();
    const encrypter = AesCrypter.createAES256CbcEncrypter(iv, encryptionKey);
    const macProcessorStream = Hasher.hmacSha512Stream(macKey);
    macProcessorStream.update(iv);
    macProcessorStream.update(ephemeralKey.publicKey.serialize());

    const encryptedDataStream = plainDataStream.pipe(encrypter);
    encryptedDataStream.on("end", () => {
      outDataStream.end();
    });
    encryptedDataStream.on("data", (chunk: Buffer) => {
      macProcessorStream.update(chunk);
      outDataStream.push(chunk);
    });

    return {
      iv: iv,
      ephemeralPublicKey: Buffer.from(ephemeralKey.publicKey.serialize()),
      cipherData: outDataStream,
      mac: macProcessorStream,
    };
  }

  static decryptECIESStream(
    encryptedData: Omit<EncryptedData<Buffer, Readable>, "mac"> & {
      mac: Buffer;
    },
    privateKeyBuffer: Buffer,
  ): Readable {
    const secretKey = new SecretKey();
    secretKey.deserialize(new Uint8Array(privateKeyBuffer));
    const publicKey = new PublicKey();
    publicKey.deserialize(new Uint8Array(encryptedData.ephemeralPublicKey));
    const px = secretKey.getDHKeyExchange(publicKey);
    const hash = Hasher.sha512Buffer(Buffer.from(px.serialize()));
    const encryptionKey = Buffer.from(hash.subarray(0, KEY_LENGTH_IN_BYTE));
    const macKey = Buffer.from(hash.subarray(KEY_LENGTH_IN_BYTE));

    // Streams
    const returnStream = new PassThrough();
    const macDataStream = new PassThrough();
    const decrypter = AesCrypter.createAES256CbcDecrypter(
      encryptedData.iv,
      encryptionKey,
    );
    const decryptedStream = encryptedData.cipherData.pipe(decrypter);
    encryptedData.cipherData.pipe(macDataStream);

    // State flags
    let macReady = false;
    let decryptionReady = false;

    // Function for validating mac called by mac and data streams:
    const validateMac = (): void => {
      if (!macReady || !decryptionReady) {
        return;
      }

      const calculatedMac = macHasher.digest();
      if (!timingSafeEqual(encryptedData.mac, calculatedMac)) {
        returnStream.emit("error", new Error("BadMAC!"));
        return;
      }

      returnStream.end();
    };

    // MAC
    const macHasher = Hasher.hmacSha512Stream(macKey);
    macHasher.update(encryptedData.iv);
    macHasher.update(encryptedData.ephemeralPublicKey);

    // Setting up macDataStream to construct MAC for the data stream
    macDataStream.on("finish", () => {
      macReady = true;
      validateMac();
    });
    macDataStream.on("data", (chunk: Buffer) => {
      macHasher.update(chunk);
    });

    decryptedStream.on("end", () => {
      decryptionReady = true;
      validateMac();
    });
    decryptedStream.on("data", (chunk: Buffer) => {
      returnStream.push(chunk);
    });

    return returnStream;
  }
}
