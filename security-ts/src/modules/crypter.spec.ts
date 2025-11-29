import { Readable } from "stream";
import { Crypter } from "./crypter";
import { drainStreamToBuffer } from "../utils/stream-util";

describe("Crypter", () => {
  test("generateKeyPair structure", () => {
    const keyPair = Crypter.generateKeyPairHex();

    expect(keyPair).toBeDefined();
    expect(typeof keyPair).toBe("object");
    expect(keyPair.privateKey).toBeDefined();
    expect(typeof keyPair.privateKey).toBe("string");
    expect(keyPair.publicKey).toBeDefined();
    expect(typeof keyPair.publicKey).toBe("string");
  });

  test("sign and verify", () => {
    const keyPair = {
      privateKey:
        "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c",
      publicKey:
        "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8",
    };
    const data = "My Test Data";
    const signature = Crypter.signHex(data, "utf8", keyPair.privateKey);
    const verify = Crypter.verifyHex(
      data,
      "utf8",
      signature,
      keyPair.publicKey,
    );

    expect(signature).toBeDefined();
    expect(typeof signature).toBe("string");
    expect(signature).toBe(
      "011d4a39bf3e93ab45e5f42a30cbef10e0b6de01318893e2b20ed41531c08760c9749f48734d386e93ba96fc93f6454ee1e96de53409e873250314a45ba6126bc2",
    );
    expect(verify).toBeDefined();
    expect(typeof verify).toBe("boolean");
    expect(verify).toBe(true);
  });

  test("sign and verify modified message", () => {
    const keyPair = {
      privateKey:
        "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c",
      publicKey:
        "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8",
    };
    const data = "My Test Data";
    const signature = Crypter.signHex(data, "utf8", keyPair.privateKey);
    const verify = Crypter.verifyHex(
      data + "Modified",
      "utf8",
      signature,
      keyPair.publicKey,
    );

    expect(signature).toBeDefined();
    expect(typeof signature).toBe("string");
    expect(signature).toBe(
      "011d4a39bf3e93ab45e5f42a30cbef10e0b6de01318893e2b20ed41531c08760c9749f48734d386e93ba96fc93f6454ee1e96de53409e873250314a45ba6126bc2",
    );
    expect(verify).toBeDefined();
    expect(typeof verify).toBe("boolean");
    expect(verify).toBe(false);
  });

  test("normalize to lower-s and verify", () => {
    const keyPair = {
      privateKey:
        "802d92e40dbe885ed959a7e9dcab23a4dc7506abeed81df3ea678f8e35810425",
      publicKey:
        "0445f713e503ac4b6782a938649dbcc2782c48dd3aee3787b3633fe7c6cb56af2cc8af19c54b6722c47c5a01fe389a769935e8fa75843045c672d47cb205df8203",
    };
    const hash =
      "bf565e4a0dd74e33faf2ff08517187f59c074834bc2ca0ad239e39ef508231de";
    const signature =
      "000541dc5b8be70ef85d6ed4d1ffcbe3079c89a448058b3b677d6cb7ded440c776eeb2dcc85385d9203466404a91bdc2f927d6b24978f13c2850c3ba735ccb0f7b";
    const notNormalized = Crypter.verifyHashHex(
      hash,
      signature,
      keyPair.publicKey,
    );
    const normalized = Crypter.verifyHashHex(
      hash,
      signature,
      keyPair.publicKey,
      true,
    );

    expect(notNormalized).toBeDefined();
    expect(notNormalized).toBe(false);
    expect(normalized).toBeDefined();
    expect(normalized).toBe(true);
  });

  test("ECIES encryption structure", () => {
    const keyPair = {
      privateKey:
        "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c",
      publicKey:
        "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8",
    };
    const data = "My super secret data!";
    const encrypted = Crypter.encryptECIESBuffer(
      Buffer.from(data, "utf8"),
      Buffer.from(keyPair.publicKey, "hex"),
    );

    expect(encrypted).toBeDefined();
    expect(typeof encrypted).toBe("object");
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.ephemeralPublicKey).toBeDefined();
    expect(encrypted.cipherData).toBeDefined();
    expect(encrypted.mac).toBeDefined();
  });

  test("ECIES encryption end decryption", () => {
    const keyPair = {
      privateKey:
        "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c",
      publicKey:
        "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8",
    };
    const data = "My super secret data!";
    const encrypted = Crypter.encryptECIESBuffer(
      Buffer.from(data, "utf8"),
      Buffer.from(keyPair.publicKey, "hex"),
    );
    const decrypted = Crypter.decryptECIESBuffer(
      encrypted,
      Buffer.from(keyPair.privateKey, "hex"),
    );
    expect(encrypted).toBeDefined();
    expect(decrypted).toBeDefined();
    expect(decrypted.toString("utf8")).toBe(data);
  });

  test("ECIES stream encryption & decryption", async () => {
    const keyPair = {
      privateKey:
        "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c",
      publicKey:
        "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8",
    };
    const stringData = "My super secret data!";
    const data = Readable.from(
      stringData
        .split(" ")
        .map((x, i, arr) => x + (i < arr.length - 1 ? " " : "")),
    );
    const encrypted = Crypter.encryptECIESStream(
      data,
      Buffer.from(keyPair.publicKey, "hex"),
    );

    expect(encrypted).toBeDefined();
    expect(encrypted.iv).toBeDefined();
    expect(encrypted.mac).toBeDefined();
    expect(encrypted.cipherData).toBeDefined();
    expect(encrypted.ephemeralPublicKey).toBeDefined();

    // We must wait for the data stream here to be drained,
    // only then we can call digest on the mac stream.
    // This means unfortunately there is no direct way to link
    // encryption - decryption process.

    const [drainedData, drainedMac] = await new Promise<Iterable<Buffer>>(
      (resolve) => {
        const dataCollector: Buffer[] = [];

        encrypted.cipherData.on("data", (chunk) => {
          dataCollector.push(
            chunk instanceof Buffer ? chunk : Buffer.from(chunk),
          );
        });
        encrypted.cipherData.on("end", () => {
          resolve([Buffer.concat(dataCollector), encrypted.mac.digest()]);
        });
      },
    );

    const decrypted = Crypter.decryptECIESStream(
      {
        iv: encrypted.iv,
        mac: Buffer.from(drainedMac),
        cipherData: Readable.from(drainedData),
        ephemeralPublicKey: encrypted.ephemeralPublicKey,
      },
      Buffer.from(keyPair.privateKey, "hex"),
    );

    const decryptedData = await drainStreamToBuffer(decrypted);

    expect(decrypted).toBeDefined();
    expect(decryptedData.toString("utf8")).toBe(stringData);
  });
});
