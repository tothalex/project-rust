/* eslint-disable max-len */
import { Hasher } from "./hasher";

describe("Hasher", () => {
  test("Generate password hash", async () => {
    try {
      const password = "MyTestPassword!";
      const pwdHash = await Hasher.getPasswordHash(password, 12);
      expect(typeof pwdHash).toBe("string");
    } catch (error) {
      throw new Error((<Error>error).message);
    }
  });

  test("Check password", async () => {
    const password = "MyTestPassword!";
    const pwdCheckResult = await Hasher.checkPassword(
      password,
      "$2b$12$VOUcKk3VGKGbaIXwEwyeIe7eoEAqeixs731XdoA7XjCiNjjF5XQOO",
    );
    expect(pwdCheckResult).toBe(true);
  });

  test("Check wrong password", async () => {
    const password = "MyWrongPassword!";
    const pwdCheckResult = await Hasher.checkPassword(
      password,
      "$2b$12$VOUcKk3VGKGbaIXwEwyeIe7eoEAqeixs731XdoA7XjCiNjjF5XQOO",
    );
    expect(pwdCheckResult).toBe(false);
  });

  test("Check `sha256Hex` with string", () => {
    const hash = Hasher.sha256Hex("Test", "utf8");
    expect(hash).toBe(
      "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
    );
  });

  test("Check `sha256Buffer` with string", () => {
    const hash = Hasher.sha256Buffer(Buffer.from("Test", "utf8"));
    expect(hash.toString("hex")).toBe(
      "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25",
    );
  });

  test("Check `sha512Hex` with string", () => {
    const hash = Hasher.sha512Hex("Test", "utf8");
    expect(hash).toBe(
      "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
    );
  });

  test("Check `sha512Buffer` with string", () => {
    const hash = Hasher.sha512Buffer(Buffer.from("Test", "utf8"));
    expect(hash.toString("hex")).toBe(
      "c6ee9e33cf5c6715a1d148fd73f7318884b41adcb916021e2bc0e800a5c5dd97f5142178f6ae88c8fdd98e1afb0ce4c8d2c54b5f37b30b7da1997bb33b0b8a31",
    );
  });

  test("Check `hmacSha512Hex` with string", () => {
    const hmac = Hasher.hmacSha512Hex("TestKey", "utf8", "TestData", "utf8");
    expect(hmac).toBe(
      "8bbc988679ab3b2e1f83e12d38080ee5cf7a6cb3ba69082eeb059739b1e9e78093e8c238aeb13d7e91296817a221845788192f37559e481fef7e35873319e039",
    );
  });

  test("Check `hmacSha512Buffer` with string", () => {
    const hmac = Hasher.hmacSha512Buffer(
      Buffer.from("TestKey", "utf8"),
      Buffer.from("TestData", "utf8"),
    );
    expect(hmac.toString("hex")).toBe(
      "8bbc988679ab3b2e1f83e12d38080ee5cf7a6cb3ba69082eeb059739b1e9e78093e8c238aeb13d7e91296817a221845788192f37559e481fef7e35873319e039",
    );
  });

  test("Check `hmacSha256Hex` with string", () => {
    const hmac = Hasher.hmacSha256Hex("TestKey", "utf8", "TestData", "utf8");
    expect(hmac).toBe(
      "f8125d567c7a2a70a0e4c0197ea4f5b790ba1ebfa5dad1865579f88ba935340e",
    );
  });

  test("Check `hmacSha256Buffer` with buffer", () => {
    const hmac = Hasher.hmacSha256Buffer(
      Buffer.from("TestKey", "utf8"),
      Buffer.from("TestData", "utf8"),
    );
    expect(hmac.toString("hex")).toBe(
      "f8125d567c7a2a70a0e4c0197ea4f5b790ba1ebfa5dad1865579f88ba935340e",
    );
  });

  test("Check `createHmacSha256` with string", () => {
    const hmac = Hasher.createHmacSha256("TestKey", "utf8");
    hmac.update("TestData");
    expect(hmac.digest("hex")).toBe(
      "f8125d567c7a2a70a0e4c0197ea4f5b790ba1ebfa5dad1865579f88ba935340e",
    );
  });
});
