import type { HexString } from "../types/utils.types";
import type { PublicKey, SecretKey } from "./bls-helper";

export type KeyPair<
  T = SecretKey | Uint8Array | Buffer | HexString,
  U = PublicKey | Uint8Array | Buffer | HexString,
> = {
  secretKey: T;
  publicKey: U;
};

export type EncryptedData<T = HexString | Buffer, Data = T> = {
  iv: T;
  ephemeralPublicKey: T;
  cipherData: Data;
  mac: Data;
};
