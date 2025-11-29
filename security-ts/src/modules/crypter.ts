import secp256k1 from "secp256k1";

import { Hmac } from "crypto";
import { Hasher } from "./hasher";
import { Randomer } from "./randomer";
import { Readable } from "node:stream";
import { HexString } from "../types/utils.types";
import { AesCrypter } from "./aes-crypter";
import { PassThrough } from "stream";
import { timingSafeEqual } from "node:crypto";

export type ECIESBufferPayload<T = Buffer> = {
  iv: T;
  ephemeralPublicKey: T;
  cipherData: T;
  mac: T;
};

type ECIESStreamPayload = {
  iv: Buffer;
  ephemeralPublicKey: Buffer;
  cipherData: Readable;
  mac: Hmac;
};
type ECIESStreamEcryptedPayload = {
  iv: Buffer;
  ephemeralPublicKey: Buffer;
  cipherData: Readable;
  mac: Buffer;
};
type KeyPair<T = HexString> = { publicKey: T; privateKey: T };

const KEY_LENGTH = 32;

const RANDOM_LENGTH = 16;
/**
 * Handles secp256k1 functionality
 */
export class Crypter {
  static generateKeyPairHex(): KeyPair<HexString> {
    const result = Crypter.generateKeyPairBuffer();

    return {
      privateKey: result.privateKey.toString("hex"),
      publicKey: result.publicKey.toString("hex"),
    };
  }

  static generateKeyPairBuffer(): KeyPair<Buffer> {
    let privateKey;

    do {
      privateKey = Randomer.randomBytes(KEY_LENGTH, true);
    } while (!secp256k1.privateKeyVerify(privateKey));

    const publicKey = Buffer.from(secp256k1.publicKeyCreate(privateKey, false));

    return {
      privateKey,
      publicKey,
    };
  }

  static checkPrivateKeyHex(
    privateKey: HexString,
    publicKey: HexString,
  ): boolean {
    return Crypter.checkPrivateKeyBuffer(
      Buffer.from(privateKey, "hex"),
      Buffer.from(publicKey, "hex"),
    );
  }

  static checkPrivateKeyBuffer(
    privateKeyBuffer: Buffer,
    publicKeyBuffer: Buffer,
  ): boolean {
    const derivedPublicKey = Buffer.from(
      secp256k1.publicKeyCreate(privateKeyBuffer, false),
    );

    if (!timingSafeEqual(derivedPublicKey, publicKeyBuffer)) {
      throw new Error("BadKeyPair!");
    }

    return true;
  }

  static generatePublicKeyHex(privateKey: HexString): HexString {
    return Buffer.from(
      Crypter.generatePublicKeyBuffer(Buffer.from(privateKey, "hex")),
    ).toString("hex");
  }

  static generatePublicKeyBuffer(privateKeyBuffer: Buffer): Uint8Array {
    return secp256k1.publicKeyCreate(privateKeyBuffer, false);
  }

  static signHashHex = (hash: HexString, privateKey: HexString): string => {
    const result = Crypter.signHashBuffer(
      Buffer.from(hash, "hex"),
      Buffer.from(privateKey, "hex"),
    );

    return result.toString("hex");
  };

  static signHashBuffer(hashBuffer: Buffer, privateKeyBuffer: Buffer): Buffer {
    const sig = secp256k1.ecdsaSign(hashBuffer, privateKeyBuffer);

    return Buffer.concat([Buffer.from([sig.recid]), sig.signature]);
  }

  static signHex(
    data: string,
    dataEncodig: BufferEncoding,
    privateKey: string,
  ): HexString {
    const result = Crypter.signHashBuffer(
      Hasher.sha256Buffer(Buffer.from(data, dataEncodig)),
      Buffer.from(privateKey, "hex"),
    );

    return result.toString("hex");
  }

  static signBuffer(dataBuffer: Buffer, privateKeyBuffer: Buffer): Buffer {
    return Crypter.signHashBuffer(
      Hasher.sha256Buffer(dataBuffer),
      privateKeyBuffer,
    );
  }

  static verifyHashHex(
    hash: HexString,
    signature: HexString,
    publicKey: HexString,
    normalize = false,
  ): boolean {
    return Crypter.verifyHashBuffer(
      Buffer.from(hash, "hex"),
      Buffer.from(signature, "hex"),
      Buffer.from(publicKey, "hex"),
      normalize,
    );
  }

  static verifyHashBuffer(
    hashBuffer: Buffer,
    signatureBuffer: Buffer,
    publicKeyBuffer: Buffer,
    normalize = false,
  ): boolean {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const recovery = signatureBuffer[0];
    const sigBuffer = signatureBuffer.slice(1);

    if (normalize) {
      return secp256k1.ecdsaVerify(
        secp256k1.signatureNormalize(sigBuffer),
        hashBuffer,
        publicKeyBuffer,
      );
    } else {
      return secp256k1.ecdsaVerify(sigBuffer, hashBuffer, publicKeyBuffer);
    }
  }

  static verifyHex(
    data: string,
    dataEncodig: BufferEncoding,
    signature: string,
    publicKey: string,
    normalize = false,
  ): boolean {
    return Crypter.verifyHashBuffer(
      Hasher.sha256Buffer(Buffer.from(data, dataEncodig)),
      Buffer.from(signature, "hex"),
      Buffer.from(publicKey, "hex"),
      normalize,
    );
  }

  static verifyBuffer(
    dataBuffer: Buffer,
    signatureBuffer: Buffer,
    publicKeyBuffer: Buffer,
    normalize = false,
  ): boolean {
    return Crypter.verifyHashBuffer(
      Hasher.sha256Buffer(dataBuffer),
      signatureBuffer,
      publicKeyBuffer,
      normalize,
    );
  }

  // https://cryptobook.nakov.com/asymmetric-key-ciphers/ecies-public-key-encryption
  static encryptECIESBuffer(
    plainDataBuffer: Buffer,
    publicKeyBuffer: Buffer,
  ): ECIESBufferPayload {
    const ephemeralKey = Crypter.generateKeyPairBuffer();
    const px = secp256k1.ecdh(publicKeyBuffer, ephemeralKey.privateKey);
    const hash = Hasher.sha512Buffer(px);
    const encryptionKey = hash.slice(0, KEY_LENGTH);
    const macKey = hash.slice(KEY_LENGTH);
    const iv = Randomer.randomBytes(RANDOM_LENGTH, true);
    const cipherData = AesCrypter.encryptAES256CbcBuffer(
      plainDataBuffer,
      iv,
      encryptionKey,
    );
    const dataToMac = Buffer.concat([iv, ephemeralKey.publicKey, cipherData]);
    const mac = Hasher.hmacSha512Buffer(macKey, dataToMac);

    return {
      iv,
      ephemeralPublicKey: ephemeralKey.publicKey,
      cipherData,
      mac,
    };
  }

  static encryptECIESStream(
    plainDataStream: Readable,
    publicKeyBuffer: Buffer,
  ): ECIESStreamPayload {
    const ephemeralKey = Crypter.generateKeyPairBuffer();
    const px = secp256k1.ecdh(publicKeyBuffer, ephemeralKey.privateKey);
    const hash = Hasher.sha512Buffer(px);
    const encryptionKey = hash.slice(0, KEY_LENGTH);
    const macKey = hash.slice(KEY_LENGTH);
    const iv = Randomer.randomBytes(RANDOM_LENGTH, true);
    const dataEncrypter = AesCrypter.createAES256CbcEncrypter(
      iv,
      encryptionKey,
    );

    const encryptedDataStream = plainDataStream.pipe(dataEncrypter);

    const outDataStream = new PassThrough();
    const macProcessorStream = Hasher.hmacSha512Stream(macKey);
    macProcessorStream.update(iv);
    macProcessorStream.update(ephemeralKey.publicKey);

    encryptedDataStream.on("end", () => {
      outDataStream.end();
    });
    encryptedDataStream.on("data", (chunk: Buffer) => {
      macProcessorStream.update(chunk);
      outDataStream.push(chunk);
    });

    return {
      iv,
      ephemeralPublicKey: ephemeralKey.publicKey,
      cipherData: outDataStream,
      mac: macProcessorStream,
    };
  }

  static decryptECIESBuffer(
    encryptedData: ECIESBufferPayload,
    privateKeyBuffer: Buffer,
  ): Buffer {
    const px = secp256k1.ecdh(
      encryptedData.ephemeralPublicKey,
      privateKeyBuffer,
    );
    const hash = Hasher.sha512Buffer(px);
    const encryptionKey = hash.slice(0, KEY_LENGTH);
    const macKey = hash.slice(KEY_LENGTH);
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

  static decryptECIESStream(
    encryptedData: ECIESStreamEcryptedPayload,
    privateKeyBuffer: Buffer,
  ): Readable {
    const px = secp256k1.ecdh(
      encryptedData.ephemeralPublicKey,
      privateKeyBuffer,
    );
    const hash = Hasher.sha512Buffer(px);
    const encryptionKey = hash.slice(0, KEY_LENGTH);
    const macKey = hash.slice(KEY_LENGTH);

    // State flags
    let macReady = false;
    let decryptionReady = false;

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

    // Responsible only for hash creation
    const returnStream = new PassThrough();
    const macDataStream = new PassThrough();
    const decrypter = AesCrypter.createAES256CbcDecrypter(
      encryptedData.iv,
      encryptionKey,
    );
    const decryptedStream = encryptedData.cipherData.pipe(decrypter);

    const macHasher = Hasher.hmacSha512Stream(macKey);
    macHasher.update(encryptedData.iv);
    macHasher.update(encryptedData.ephemeralPublicKey);

    // Data hole for eating up the data for mac
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
    decryptedStream.on("data", (chunk: unknown) => {
      returnStream.push(chunk);
    });

    encryptedData.cipherData.pipe(macDataStream);

    return returnStream;
  }
}
