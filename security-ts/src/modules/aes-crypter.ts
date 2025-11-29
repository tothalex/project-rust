import { Randomer } from "./randomer";
import {
  scryptSync,
  createCipheriv,
  createDecipheriv,
  BinaryLike,
  Cipher,
  Decipher,
} from "crypto";

const SALT_LENGTH_IN_BYTE = 64;
const KEY_LENGTH_IN_BYTE = 32;
const IV_LENGTH_IN_BYTE = 16;

export class AesCrypter {
  static generateAESKeyHex(password: string): { key: string; iv: string } {
    // salt is minimum 512bit long
    // Read more: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
    return {
      key: scryptSync(
        password,
        Randomer.randomBytes(SALT_LENGTH_IN_BYTE, true),
        KEY_LENGTH_IN_BYTE,
      ).toString("hex"),
      iv: Randomer.randomBytes(IV_LENGTH_IN_BYTE, true).toString("hex"),
    };
  }

  static generateAESKeyBuffer(password: string): { key: Buffer; iv: Buffer } {
    // salt is minimum 512bit long
    // Read more: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
    return {
      key: scryptSync(
        password,
        Randomer.randomBytes(SALT_LENGTH_IN_BYTE, true),
        KEY_LENGTH_IN_BYTE,
      ),
      iv: Randomer.randomBytes(IV_LENGTH_IN_BYTE, true),
    };
  }

  static encryptAES256CbcHex(
    plaintext: string,
    iv: string,
    key: string,
  ): string {
    return AesCrypter.encryptAES256CbcBuffer(
      Buffer.from(plaintext),
      Buffer.from(iv, "hex"),
      Buffer.from(key, "hex"),
    ).toString("hex");
  }

  static encryptAES256CbcBuffer(
    plainBuffer: Buffer,
    ivBuffer: Buffer,
    keyBuffer: Buffer,
  ): Buffer {
    const cipher = createCipheriv("aes-256-cbc", keyBuffer, ivBuffer);
    const firstChunk = cipher.update(plainBuffer);
    const secondChunk = cipher.final();
    // first 16 item is the IV
    return Buffer.concat([firstChunk, secondChunk]);
  }

  static createAES256CbcEncrypter(ivBuffer: Buffer, keyBuffer: Buffer): Cipher {
    return createCipheriv("aes-256-cbc", keyBuffer, ivBuffer);
  }

  static decryptAES256CbcHex(
    ciphertext: string,
    iv: string,
    key: string,
  ): Buffer {
    return AesCrypter.decryptAES256CbcBuffer(
      Buffer.from(ciphertext, "hex"),
      Buffer.from(iv, "hex"),
      Buffer.from(key, "hex"),
    );
  }

  static decryptAES256CbcBuffer = (
    cipherBuffer: Buffer,
    ivBuffer: BinaryLike,
    keyBuffer: Buffer,
  ): Buffer => {
    // cipherBuffer first 16 item is the IV
    const cipher = createDecipheriv("aes-256-cbc", keyBuffer, ivBuffer);
    const firstChunk = cipher.update(cipherBuffer);
    const secondChunk = cipher.final();

    return Buffer.concat([firstChunk, secondChunk]);
  };

  static createAES256CbcDecrypter = (
    ivBuffer: BinaryLike,
    keyBuffer: Buffer,
  ): Decipher => {
    // cipherBuffer first 16 item is the IV
    return createDecipheriv("aes-256-cbc", keyBuffer, ivBuffer);
  };
}
