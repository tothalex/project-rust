/* eslint-disable max-len, @typescript-eslint/no-non-null-assertion */
import { JWT } from "./jwt";

class NoErrorThrownError extends Error {}

async function getError<TError extends Error>(
  call: () => unknown,
): Promise<TError> {
  try {
    await call();

    throw new NoErrorThrownError();
  } catch (error: unknown) {
    return error as TError;
  }
}

describe("JWT", () => {
  test("Testing generate and decode Token", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      { payLoadData: "My toke data" },
    );
    const decoded = JWT.decodeToken(token);
    expect(token).toBeDefined();
    expect(typeof token).toBe("string");
    expect(decoded).toBeDefined();
    expect(typeof decoded).toBe("object");
    expect(decoded.header).toBeDefined();
    expect(typeof decoded.header).toBe("object");
    expect(decoded.header["typ"]).toBeDefined();
    expect(decoded.header["typ"]).toBe("JWT");
    expect(decoded.header["alg"]).toBeDefined();
    expect(decoded.header["alg"]).toBe("ES256K");
    //throw new Error (JSON.stringify(decoded.payload, null, 2));
    expect(decoded.payload).toBeDefined();
    expect(typeof decoded.payload).toBe("object");
    expect(decoded.payload.iss).toBeDefined();
    expect(decoded.payload.iss).toBe("Issuer");
    expect(decoded.payload.sub).toBeDefined();
    expect(decoded.payload.sub).toBe("Subject");
    expect(decoded.payload.aud).toBeDefined();
    expect(typeof decoded.payload.aud).toBe("object");
    expect(decoded.payload.aud!.length).toBe(2);
    expect(decoded.payload?.aud![0]).toBe("Role1");
    expect(decoded.payload?.aud![1]).toBe("Role2");
    expect(decoded.payload.exp).toBeDefined();
    expect(typeof decoded.payload.exp).toBe("number");
    expect(decoded.payload["payLoadData"]).toBeDefined();
    expect(decoded.payload["payLoadData"]).toBe("My toke data");
    expect(decoded.signature).toBeDefined();
    expect(typeof decoded.signature).toBe("string");
  });

  test("Testing verify token", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      { payLoadData: "My toke data" },
    );
    const verified = await JWT.verifyToken(
      token,
      publicKey,
      "Issuer",
      "Subject",
      ["Role1"],
    );

    expect(verified).toBeDefined();
    expect(typeof verified).toBe("object");
  });

  test("Testing verify token - Without audience", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      { payLoadData: "My toke data" },
    );
    const verified = await JWT.verifyToken(
      token,
      publicKey,
      "Issuer",
      "Subject",
    );

    expect(verified).toBeDefined();
    expect(typeof verified).toBe("object");
  });

  test("Testing verify token - Without subject", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      { payLoadData: "My toke data" },
    );
    const verified = await JWT.verifyToken(token, publicKey, "Issuer", null, [
      "Role1",
    ]);

    expect(verified).toBeDefined();
    expect(typeof verified).toBe("object");
  });

  test("Testing verify token - Without subject and audience", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      { payLoadData: "My toke data" },
    );
    const verified = await JWT.verifyToken(token, publicKey, "Issuer");

    expect(verified).toBeDefined();
    expect(typeof verified).toBe("object");
  });

  test("Testing verify token - Invalid Issuer", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      {
        payLoadData: "My toke data",
      },
    );

    const error = await getError(async () => {
      await JWT.verifyToken(token, publicKey, "IssuerERROR", "Subject", [
        "Role1",
      ]);
    });
    expect(error).not.toBeInstanceOf(NoErrorThrownError);
    expect(error.message).toBe("ERR_JWT_CLAIM_VALIDATION_FAILED_ISS");
  });

  test("Testing verify token - Invalid Subject", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      {
        payLoadData: "My toke data",
      },
    );

    const error = await getError(async () => {
      await JWT.verifyToken(token, publicKey, "Issuer", "SubjectERROR", [
        "Role1",
      ]);
    });
    expect(error).not.toBeInstanceOf(NoErrorThrownError);
    expect(error.message).toBe("ERR_JWT_CLAIM_VALIDATION_FAILED_SUB");
  });

  test("Testing verify token - Invalid audience", async () => {
    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "10s",
      {
        payLoadData: "My toke data",
      },
    );

    const error = await getError(async () => {
      await JWT.verifyToken(token, publicKey, "Issuer", "Subject", [
        "Role1ERROR",
      ]);
    });

    expect(error).not.toBeInstanceOf(NoErrorThrownError);
    expect(error.message).toBe("ERR_JWT_CLAIM_VALIDATION_FAILED_AUD");
  });

  test("Testing verify token - Expired", async () => {
    function sleep(ms: number): Promise<void> {
      return new Promise((resolve) => {
        setTimeout(() => resolve(), ms);
      });
    }

    const privateKey =
      "b427895f41333d18e7c920d0e37cd5b8417344723d3cc2999f3bf98149f8fa8c";
    const publicKey =
      "04626316569412a141c7719d05af4ec05f77ce942b3e081d83019a18ce9348b9548c4e9b0029f34c50511d36cfde3237be8cc75b82b5ed9d698f286bb86c601fa8";
    const token = await JWT.createToken(
      privateKey,
      "Issuer",
      "Subject",
      ["Role1", "Role2"],
      "1s",
      { payLoadData: "My toke data" },
    );
    const error = await getError(async () => {
      await sleep(7 * 1000); //clockTolerance is 5s!!!
      await JWT.verifyToken(token, publicKey, "Issuer", "Subject", ["Role1"]);
    });

    expect(error).not.toBeInstanceOf(NoErrorThrownError);
    expect(error.message).toBe("ERR_JWT_EXPIRED");
  }, 15000);
});
