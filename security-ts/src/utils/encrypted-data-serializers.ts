import type { HexString } from "../types/utils.types";
import type { EncryptedData } from "../modules/hiver.types";

export const serializeBufferedEncryptedDataToHexString = (input: EncryptedData<Buffer, Buffer>): EncryptedData<HexString, HexString> => {
	return {
		iv: input.iv.toString("hex"),
		mac: input.mac.toString("hex"),
		cipherData: input.cipherData.toString("hex"),
		ephemeralPublicKey: input.ephemeralPublicKey.toString("hex"),
	};
};

export const deSerializeHexStringEncryptedDataToBuffer = (input: EncryptedData<HexString, HexString>): EncryptedData<Buffer, Buffer> => {
	return {
		iv: Buffer.from(input.iv, "hex"),
		mac: Buffer.from(input.mac, "hex"),
		cipherData: Buffer.from(input.cipherData, "hex"),
		ephemeralPublicKey: Buffer.from(input.ephemeralPublicKey, "hex"),
	};
};
