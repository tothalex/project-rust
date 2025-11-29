export type HexString = string;

/* eslint-disable @typescript-eslint/no-explicit-any */
export type AnyObject = { [key: string | symbol]: any };

export interface IActorMember {
  id: string;
  pm: string;
}

export interface IActorDataResponse {
  id: HexString;
  pm: HexString;
  displayText: string;
  sharedDeviceId: string | null;
  sharedDevicePm: string | null;
}

export interface IActorContractParticipant {
  member: IActorMember;
  profile?: IActorMember;
}

export interface IActorShareData {
  shareCode: string;
  subjectActorId: string;
  subjectActorType: string;
  hatId: string | null;
  fromActorId: string | null;
  roleCode: string;
  toActorId: string;
  ownerActorId?: string;
}

export interface IESH<T, U> {
  receiverId: T;
  receiverPK: U;
  esh: string;
}

export interface IContribution<TId = HexString, TPublicKey = HexString> {
  pg: TPublicKey[];
  esh: IESH<TId, TPublicKey>[];
}

export interface IReceivedContribution<
  TId = HexString,
  TPublicKey = HexString,
> {
  senderId: TId;
  contribution: IContribution<TId, TPublicKey>;
}

export interface IActorContractResponse {
  id: string;
  contributors: IActorMember[];
  actor: IActorDataResponse;
  newParticipants: IActorContractParticipant[];
  threshold: number;
  actorShare: IActorShareData;
  newMembers: IActorMember[];
  contributions: IReceivedContribution[];
  isFinalized: boolean;
}

export interface IHatDescriptor {
  hatActorId: string;
  hatActorName?: string;
  ownerActorId: string;
  ownerActorPm: string;
  ownerActorName?: string;
  roleCode: string;
  toActorId: string;
  toActorName?: string;
  shareCode: string;
}

export interface IEmailResponse {
  uid: string;
  email: string;
  isPrimary: boolean;
  isVerified: boolean;
}

export interface IPhoneNumberDTO {
  uid: string;
  countryCode: string;
  lineNumber: string;
  merged: string;
  isPrimary: boolean;
  isVerified: boolean;
  verifiedAt: Date | null;
}

export interface ILookupDTO<T extends AnyObject = AnyObject> {
  entityName?: string;
  code: string;
  templateCode?: ILookupDTO;
  displayText?: string;
  type?: string;
  subtype?: string;
  method?: string;
  submethod?: string;
  classification?: T;
}

export interface IUserIdProcLookupResponse extends ILookupDTO {
  state: string;
}

export interface IUserResponse {
  code: string;
  type: string;
  subtype: string;
  method: string;
  submethod: string;
  displayText: string;
  isCompany: boolean;
  email: IEmailResponse;
  phoneNumber: IPhoneNumberDTO | null;
  discriminator: string;
  missions: string[];
  language: ILookupDTO;
  state: string;
  actUserIdProc: IUserIdProcLookupResponse;
  refereeCode: string;
  referrerCode: string;
  distributorCode: string;
}

export interface IActorData {
  id: HexString;
  pm: HexString;
  sm: HexString;
  pg?: HexString;
  displayText: string;
  sharedDeviceId?: string;
  sharedDevicePm?: string;
  creatorSharedList: IActorMember[];
}

export interface IActorContract {
  id: string;
  contributors: IActorMember[];
  actor: IActorData;
  newParticipants: IActorContractParticipant[];
  threshold: number;
  actorShare: IActorShareData;
  newMembers: IActorMember[];
  contributions: IReceivedContribution[];
  isFinalized: boolean;
}

export interface IContribution<TId = HexString, TPublicKey = HexString> {
  pg: TPublicKey[];
  esh: IESH<TId, TPublicKey>[];
}

export interface ISignatureChainResponse {
  actorShareCode: string;
  id: HexString;
  ph: HexString;
  sig: HexString;
  sigs?: ISignatureChainResponse[];
}

export interface IOperationResponse<T = unknown> {
  uid: HexString;
  parentOperation?: string;
  state: string;
  result?: T;
  signatureChain?: ISignatureChainResponse;
  updatedBy: HexString;
  createdAt: number;
}
