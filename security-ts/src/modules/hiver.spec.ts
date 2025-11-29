import { Hiver } from "./hiver";
import {
  deSerializeHexStringEncryptedDataToBuffer,
  serializeBufferedEncryptedDataToHexString,
} from "../utils/encrypted-data-serializers";

const keyPair = {
  publicKey:
    "64e00bdbbeffc40a1012a7d44a5a02cb62d09859c4c7bb1de29039a8acd3eb8739f3491d9e69d2e84b8f5019bab4aa06e94e9ff25563f1d2c6f769e3a1df4a17444c2b1e645cf9b3cbb5bdef9ad2ea4e940a9c7caa0e6613eabb4f8073da8e00",
  secretKey: "e298123a116d8eaced9f32f3e6482debe93074008b06670106ade44fe29b7245",
};

describe("Hiver", () => {
  beforeAll(async () => {
    await Hiver.init();
  });

  test("ECIES buffer encryption + decryption", () => {
    const jsonData = {
      displayName: "Non-Legal User",
      email: "user_3302@qantrum.io",
    };

    const encrypted = Hiver.encryptECIESBuffer(
      Buffer.from(JSON.stringify(jsonData), "utf8"),
      Buffer.from(keyPair.publicKey, "hex"),
    );

    const decrypted = Hiver.decryptECIESBuffer(
      encrypted,
      Buffer.from(keyPair.secretKey, "hex"),
    );

    expect(decrypted.toString("utf8")).toEqual(JSON.stringify(jsonData));
  });

  test("ECIES buffer encryption + decryption from string", () => {
    const jsonData = {
      displayName: "Non-Legal User",
      email: "user_3302@qantrum.io",
    };

    const encrypted = Hiver.encryptECIESBuffer(
      Buffer.from(JSON.stringify(jsonData), "utf8"),
      Buffer.from(keyPair.publicKey, "hex"),
    );

    const stringifiedForm =
      serializeBufferedEncryptedDataToHexString(encrypted);

    const deStringifiedForm =
      deSerializeHexStringEncryptedDataToBuffer(stringifiedForm);

    const decrypted = Hiver.decryptECIESBuffer(
      deStringifiedForm,
      Buffer.from(keyPair.secretKey, "hex"),
    );

    expect(decrypted.toString("utf8")).toEqual(JSON.stringify(jsonData));
  });

  test("decryption from pre-defined data", () => {
    // TODO use user_3302@email.io
    const jsonData = {
      displayName: "Non-Legal User",
      email: "user_3302@natrix.io",
    };
    const storedForm = {
      iv: "97be2c68b6dd250ba3d011337b993e26",
      mac: "894ee6b6d016cc82ac8e097a435071d65fcfc012f3c3a3c322c8a3c0c38a019e62dad4f302c3468d028dd1b2342c831f5a578e1b0d4e6bbaf482d1d6fa00b8d9",
      cipherData:
        "168dde23c5a2252c127f821cefd034d1edc7c5c72c123b4ec9c73d0bea56900b63be3ca42f35ad12edf5cfebe819a59d665bfad03183a5bb6da18c528379c86a",
      ephemeralPublicKey:
        "162703bd9b1040ac5c4b4f2ca57f488c54163172cf1465e759b6b1c358e3456de24d17a83b4d61cc1a45fa333cd13a0ae4e55e7f61e08a3077f6da94fa1854b750c2cfbcabe9e0d69b8c8e84dccc0b64353412f041d2fd6f4cf762056eec3c17",
    };

    const deStringifiedForm =
      deSerializeHexStringEncryptedDataToBuffer(storedForm);

    const decrypted = Hiver.decryptECIESBuffer(
      deStringifiedForm,
      Buffer.from(keyPair.secretKey, "hex"),
    );

    expect(decrypted.toString("utf8")).toEqual(JSON.stringify(jsonData));
  });
});
