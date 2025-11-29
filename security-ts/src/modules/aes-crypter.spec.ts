import { AesCrypter } from "./aes-crypter";

describe("AesCrypter", () => {
  test("Testing `generateKeyPair`", () => {
    const aesKey = AesCrypter.generateAESKeyHex("Password");

    expect(aesKey).toBeDefined();
    expect(typeof aesKey).toBe("object");
    expect(aesKey.key).toBeDefined();
    expect(typeof aesKey.key).toBe("string");
    expect(aesKey.iv).toBeDefined();
    expect(typeof aesKey.iv).toBe("string");
  });

  test("Testing string encryption and decryption with AesCrypter", () => {
    const aesKey = AesCrypter.generateAESKeyHex("Password");
    const encryptedData = AesCrypter.encryptAES256CbcHex(
      "Test Data",
      aesKey.iv,
      aesKey.key,
    );
    const decryptedData = AesCrypter.decryptAES256CbcHex(
      encryptedData,
      aesKey.iv,
      aesKey.key,
    ).toString("utf8");

    expect(encryptedData).toBeDefined();
    expect(typeof encryptedData).toBe("string");
    expect(decryptedData).toBeDefined();
    expect(typeof decryptedData).toBe("string");
    expect(decryptedData).toBe("Test Data");
  });

  test("Testing buffer encryption and decryption with AesCrypter", () => {
    const aesKey = AesCrypter.generateAESKeyBuffer("Password");
    const data = Buffer.from("Test Data", "utf8");
    const encryptedData = AesCrypter.encryptAES256CbcBuffer(
      data,
      aesKey.iv,
      aesKey.key,
    );
    const decryptedData = AesCrypter.decryptAES256CbcBuffer(
      encryptedData,
      aesKey.iv,
      aesKey.key,
    );

    expect(encryptedData).toBeDefined();
    expect(typeof encryptedData).toBe("object");
    expect(decryptedData).toBeDefined();
    expect(typeof decryptedData).toBe("object");
    expect(decryptedData).toStrictEqual(data);
  });

  test("Testing string encryption and decryption with wrong iv length with AesCrypter", () => {
    function errorTest(): void {
      const aesKey = AesCrypter.generateAESKeyBuffer("Password");
      const data = Buffer.from("Test Data", "utf8");
      const encryptedData = AesCrypter.encryptAES256CbcBuffer(
        data,
        aesKey.iv,
        aesKey.key,
      );
      AesCrypter.decryptAES256CbcBuffer(
        encryptedData,
        "iv1234567890",
        aesKey.key,
      );
    }

    expect(errorTest).toThrowError("Invalid initialization vector");
  });

  test("Testing string encryption and decryption with wrong iv with AesCrypter", () => {
    function errorTest(): void {
      const aesKey = AesCrypter.generateAESKeyBuffer("Password");
      const data = Buffer.from("Test Data", "utf8");
      const encryptedData = AesCrypter.encryptAES256CbcBuffer(
        data,
        aesKey.iv,
        aesKey.key,
      );
      AesCrypter.decryptAES256CbcBuffer(
        encryptedData,
        "iv1234567890iviv",
        aesKey.key,
      );
    }

    expect(errorTest).toThrowError(); //new Error('error:06065064:digital envelope routines:EVP_DecryptFinal_ex:bad decrypt')
  });
});
