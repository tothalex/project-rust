import bcrypt from "bcrypt";
import crypto, { BinaryLike, Hmac } from "crypto";
import { JSONConverter } from "./json-converter";

const DEFAULT_SALT_ROUND = 11; //This is the minimumround, do not go under 11!!!

export class Hasher {
  static stringify(data: Record<never, unknown> | null): string {
    return JSON.stringify(data, JSONConverter);
  }

  static async getPasswordHash(
    password: string,
    saltRound = DEFAULT_SALT_ROUND,
  ): Promise<string> {
    return bcrypt.hash(password, saltRound);
  }

  static async checkPassword(
    password: string,
    passwordHash: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, passwordHash);
  }

  static sha256Hex(data: string, encoding?: BufferEncoding): string {
    return crypto
      .createHash("sha256")
      .update(Buffer.from(data, encoding))
      .digest("hex");
  }

  static sha256Buffer(dataBuffer: crypto.BinaryLike): Buffer {
    return crypto.createHash("sha256").update(dataBuffer).digest();
  }

  static sha512Hex(data: string, encoding: BufferEncoding): string {
    return crypto
      .createHash("sha512")
      .update(Buffer.from(data, encoding))
      .digest("hex");
  }

  static sha512Buffer(dataBuffer: BinaryLike): Buffer {
    return crypto.createHash("sha512").update(dataBuffer).digest();
  }

  static hmacSha512Hex(
    key: string,
    keyEncoding: BufferEncoding,
    data: string,
    dataEncoding: BufferEncoding,
  ): string {
    return crypto
      .createHmac("sha512", Buffer.from(key, keyEncoding))
      .update(Buffer.from(data, dataEncoding))
      .digest("hex");
  }

  static hmacSha512Buffer(
    keyBuffer: BinaryLike,
    dataBuffer: BinaryLike,
  ): Buffer {
    return crypto.createHmac("sha512", keyBuffer).update(dataBuffer).digest();
  }

  static hmacSha512Stream(keyBuffer: BinaryLike): crypto.Hmac {
    return crypto.createHmac("sha512", keyBuffer);
  }

  static createHmacSha256(key: string, keyEncoding: BufferEncoding): Hmac {
    return crypto.createHmac("sha256", Buffer.from(key, keyEncoding));
  }

  static hmacSha256Hex(
    key: string,
    keyEncoding: BufferEncoding,
    data: string,
    dataEncoding: BufferEncoding,
  ): string {
    return crypto
      .createHmac("sha256", Buffer.from(key, keyEncoding))
      .update(Buffer.from(data, dataEncoding))
      .digest("hex");
  }

  static hmacSha256Buffer(
    keyBuffer: BinaryLike,
    dataBuffer: BinaryLike,
  ): Buffer {
    return crypto.createHmac("sha256", keyBuffer).update(dataBuffer).digest();
  }

  static timingSafeEqual(
    checksum: NodeJS.ArrayBufferView,
    digest: NodeJS.ArrayBufferView,
  ): boolean {
    return crypto.timingSafeEqual(checksum, digest);
  }
}
