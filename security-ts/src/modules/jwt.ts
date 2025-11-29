import KeyEncoder from "key-encoder";

import { createPrivateKey, createPublicKey, KeyObject } from "crypto";
import {
  SignJWT,
  jwtVerify,
  JWTPayload,
  JWTVerifyOptions,
  JWTVerifyResult,
  errors,
} from "jose-node-cjs-runtime";

export type JwtTokenVerificationResult = JWTVerifyResult;

// eslint-disable-next-line @typescript-eslint/no-magic-numbers
const CACHE_ITEM_EXPIRE_TIME = 12 * 60 * 60 * 1000;

const keyEncoder = new KeyEncoder("secp256k1");
const internalKeyObjectCache: {
  [s: string]: { key: KeyObject; timestamp: number };
} = {};

enum KeyType {
  public,
  private,
}

function getKeyObject(hexKey: string, keyType: KeyType): KeyObject {
  // Find KeyObject
  let result = internalKeyObjectCache[hexKey];
  // If not exists
  if (!internalKeyObjectCache[hexKey]) {
    // Create Key object
    const keyObject = ((): KeyObject => {
      if (keyType === KeyType.private) {
        return createPrivateKey({
          key: Buffer.from(
            keyEncoder.encodePrivate(hexKey, "raw", "der"),
            "hex",
          ),
          format: "der",
          type: "sec1",
        });
      }

      return createPublicKey({
        key: Buffer.from(keyEncoder.encodePublic(hexKey, "raw", "der"), "hex"),
        format: "der",
        type: "spki",
      });
    })();

    // Save KeyObject
    result = {
      key: keyObject,
      timestamp: Date.now(),
    };
    internalKeyObjectCache[hexKey] = result;
  } else {
    // If exists, touch the timestamp
    result.timestamp = Date.now();
  }
  // Remove old keyObejcts
  for (const key in internalKeyObjectCache) {
    if (Object.prototype.hasOwnProperty.call(internalKeyObjectCache, key)) {
      if (
        internalKeyObjectCache[key].timestamp + CACHE_ITEM_EXPIRE_TIME <
        Date.now()
      ) {
        delete internalKeyObjectCache[key];
      }
    }
  }
  return result.key;
}

export class JWT {
  static async createToken<T extends Record<never, unknown>>(
    hexPrivateKey: string,
    issuer: string,
    subject: string,
    audience?: string | string[] | null,
    expiresIn: string = "",
    otherPayload?: T,
  ): Promise<string> {
    const token = new SignJWT(otherPayload ?? {})
      .setIssuer(issuer)
      .setSubject(subject)
      .setProtectedHeader({ alg: "ES256K", typ: "JWT" });

    if (expiresIn) {
      token.setExpirationTime(expiresIn);
    }
    if (audience) {
      token.setAudience(audience);
    }

    return token.sign(getKeyObject(hexPrivateKey, KeyType.private));
  }

  static decodeToken<T>(token: string): {
    header: Record<string, unknown>;
    payload: JWTPayload & T;
    signature: string;
  } {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new Error("Invalid Token format!");
    }

    const header = JSON.parse(Buffer.from(parts[0], "base64").toString("utf8"));
    const payload = JSON.parse(
      Buffer.from(parts[1], "base64").toString("utf8"),
    );
    const signature = Buffer.from(parts[2], "base64").toString("hex");

    return {
      header,
      payload,
      signature,
    };
  }

  static async verifyToken<T>(
    token: string,
    hexPublicKey: string,
    issuer: string,
    subject?: string | null,
    audience?: string | string[] | null,
  ): Promise<JWTVerifyResult & { payload: T }> {
    const options: JWTVerifyOptions = {
      issuer,
      subject: subject ?? undefined,
      audience: audience ?? undefined,
      clockTolerance: "5s",
    };

    try {
      return (await jwtVerify(
        token,
        getKeyObject(hexPublicKey, KeyType.public),
        options,
      )) as JWTVerifyResult & { payload: T };
    } catch (error) {
      if (error instanceof errors.JWTClaimValidationFailed) {
        throw new Error(error.code + "_" + error.claim.toUpperCase());
      } else if (error instanceof errors.JOSEError) {
        throw new Error(error.code);
      } else {
        throw error;
      }
    }
  }
}
