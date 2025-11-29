import { HexString } from "./utils.types";

export interface IMember<Tid, Tpm> {
	id: Tid;
	pm: Tpm;
}

export interface IESH<T = HexString, U = HexString> {
	receiverId: T;
	receiverPK: U;
	esh: string;
}

export interface IContribution<TId = HexString, TPublicKey = HexString> {
	pg: TPublicKey[];
	esh: IESH<TId, TPublicKey>[];
}

export interface IReceivedContribution<TId = HexString, TPublicKey = HexString> {
	senderId: TId;
	contribution: IContribution<TId, TPublicKey>;
}

export interface IThresholdKey<TId, TSecretKey, TPublicKey> {
	id: TId;
	sh: TSecretKey;
	ph: TPublicKey;
	phs: { id: TId; ph: TPublicKey }[];
	pg: TPublicKey;
	errors: { senderId: TId | null; receiverId: TId; reason: string }[];
}
