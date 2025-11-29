import { BLS, Fr, G1, G2, Id, SecretKey, PublicKey } from "./bls-helper";
import { HexString } from "../types/utils.types";
import {
  IMember,
  IContribution,
  IReceivedContribution,
  IESH,
  IThresholdKey,
} from "../types/thresher.types";

function _appendBuffer(
  buffer1: ArrayBufferLike,
  buffer2: ArrayBufferLike,
): Uint8Array {
  const resultBuffer = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  resultBuffer.set(new Uint8Array(buffer1), 0);
  resultBuffer.set(new Uint8Array(buffer2), buffer1.byteLength);
  return resultBuffer;
}

export function PVSHEncodeG2(
  ID: Id,
  PK: PublicKey,
  sh: SecretKey,
  helperG2: G2,
): string {
  //Algorithm 1)
  const r = new Fr();
  r.setByCSPRNG();

  //Algorithm 2)
  const Q = BLS.hashAndMapToG1(_appendBuffer(ID.serialize(), PK.serialize()));

  //Algorithm 3)
  const e = BLS.pairing(Q, BLS.mul(PK.to(G2), r));
  const eh = BLS.hashToFr(e.serialize());
  e.clear();

  //Algorithm 4)
  const c = BLS.add(sh.to(Fr), eh);

  //Algorithm 5)
  const U = BLS.mul(helperG2, r);

  //Algorithm 6)
  //const H = BLS.hashAndMapToG1(`${Q.serializeToHexStr()}.${c.serializeToHexStr()}.${U.serializeToHexStr()}`);
  const H = BLS.hashAndMapToG1(
    _appendBuffer(_appendBuffer(Q.serialize(), c.serialize()), U.serialize()),
  );

  //Algorithm 7)
  const V = BLS.mul(H, BLS.div(eh, r));
  H.clear();
  eh.clear();
  r.clear();

  //Algorithm 8)
  const resultStr = `${c.serializeToHexStr()}.${U.serializeToHexStr()}.${V.serializeToHexStr()}`;

  Q.clear();
  c.clear();
  U.clear();
  V.clear();

  return resultStr;
}

export function PVSHVerifyG2(
  ID: Id,
  PK: PublicKey,
  PH: PublicKey,
  ESH: string,
  helperG2: G2,
): string {
  // const helperG2 = helperPKGenerator.to(G2);

  const ESHArray = ESH.split(".");
  if (ESHArray.length != 3) {
    throw new Error("Invalid ESH");
  }

  const c = BLS.deserializeHexStrToFr(ESHArray[0]);
  const U = BLS.deserializeHexStrToG2(ESHArray[1]);
  const V = BLS.deserializeHexStrToG1(ESHArray[2]);

  //Algorithm 1)
  const Q = BLS.hashAndMapToG1(_appendBuffer(ID.serialize(), PK.serialize()));

  //Algorithm 2)
  //const H = BLS.hashAndMapToG1(`${Q.serializeToHexStr()}.${ESHArray[0]}.${ESHArray[1]}`);
  const H = BLS.hashAndMapToG1(
    _appendBuffer(_appendBuffer(Q.serialize(), c.serialize()), U.serialize()),
  );

  //Algorithm 3)
  const e1 = BLS.pairing(H, BLS.mul(helperG2, c));
  const e2 = BLS.mul(BLS.pairing(H, PH.to(G2)), BLS.pairing(V, U));
  //Algorithm 4)
  if (!e1.isEqual(e2)) {
    return "MISMATCH_PH_AND_CHIPER_TEXT"; //Inconsistent (c, U, V)!
  }

  return "";
}

export function PVSHDecodeG2(
  ID: Id,
  PK: PublicKey,
  SK: SecretKey,
  ESH: string,
): SecretKey {
  const ESHArray = ESH.split(".");
  if (ESHArray.length != 3) {
    throw new Error("Invalid ESH");
  }

  const c = BLS.deserializeHexStrToFr(ESHArray[0]);
  const U = BLS.deserializeHexStrToG2(ESHArray[1]);

  //Algorithm 1)
  const Q = BLS.hashAndMapToG1(_appendBuffer(ID.serialize(), PK.serialize()));

  //Algorithm 2)
  const e = BLS.pairing(BLS.mul(Q, SK.to(Fr)), U);
  const eh = BLS.hashToFr(e.serialize());
  //Algorithm 3)
  const sh = BLS.sub(c, eh);

  const result = new SecretKey();
  result.deserialize(sh.serialize());
  return result;
}

function PVSHEncodeG1(
  ID: Id,
  PK: PublicKey,
  sh: SecretKey,
  helperG1: G1,
): string {
  //Algorithm 1)
  const r = new Fr();
  r.setByCSPRNG();

  //Algorithm 2)
  const Q = BLS.hashAndMapToG2(_appendBuffer(ID.serialize(), PK.serialize()));

  //Algorithm 3)
  const e = BLS.pairing(BLS.mul(PK.to(G1), r), Q);
  const eh = BLS.hashToFr(e.serialize());
  e.clear();

  //Algorithm 4)
  const c = BLS.add(sh.to(Fr), eh);

  //Algorithm 5)
  const U = BLS.mul(helperG1, r);

  //Algorithm 6)
  // const H = BLS.hashAndMapToG2(`${Q.serializeToHexStr()}.${c.serializeToHexStr()}.${U.serializeToHexStr()}`);
  const H = BLS.hashAndMapToG2(
    _appendBuffer(_appendBuffer(Q.serialize(), c.serialize()), U.serialize()),
  );
  //Algorithm 7)
  const V = BLS.mul(H, BLS.div(eh, r));
  H.clear();
  eh.clear();
  r.clear();

  //Algorithm 8)
  const resultStr = `${c.serializeToHexStr()}.${U.serializeToHexStr()}.${V.serializeToHexStr()}`;

  Q.clear();
  c.clear();
  U.clear();
  V.clear();

  return resultStr;
}

function PVSHVerifyG1(
  ID: Id,
  PK: PublicKey,
  PH: PublicKey,
  ESH: string,
  helperG1: G1,
): string {
  const ESHArray = ESH.split(".");
  if (ESHArray.length != 3) {
    throw new Error("Invalid ESH");
  }

  const c = BLS.deserializeHexStrToFr(ESHArray[0]);
  const U = BLS.deserializeHexStrToG1(ESHArray[1]);
  const V = BLS.deserializeHexStrToG2(ESHArray[2]);

  //Algorithm 1)
  const Q = BLS.hashAndMapToG2(_appendBuffer(ID.serialize(), PK.serialize()));

  //Algorithm 2)
  //const H = BLS.hashAndMapToG2(`${Q.serializeToHexStr()}.${ESHArray[0]}.${ESHArray[1]}`);
  const H = BLS.hashAndMapToG2(
    _appendBuffer(_appendBuffer(Q.serialize(), c.serialize()), U.serialize()),
  );

  //Algorithm 3)
  const e1 = BLS.pairing(BLS.mul(helperG1, c), H);
  const e2 = BLS.mul(BLS.pairing(PH.to(G1), H), BLS.pairing(U, V));
  //Algorithm 4)
  if (!e1.isEqual(e2)) {
    return "MISMATCH_PH_AND_CHIPER_TEXT"; //Inconsistent (c, U, V)!
  }

  return "";
}

function PVSHDecodeG1(
  ID: Id,
  PK: PublicKey,
  SK: SecretKey,
  ESH: string,
): SecretKey {
  const ESHArray = ESH.split(".");
  if (ESHArray.length != 3) {
    throw new Error("Invalid ESH");
  }

  const c = BLS.deserializeHexStrToFr(ESHArray[0]);
  const U = BLS.deserializeHexStrToG1(ESHArray[1]);

  //Algorithm 1)
  const Q = BLS.hashAndMapToG2(_appendBuffer(ID.serialize(), PK.serialize()));

  //Algorithm 2)
  const e = BLS.pairing(U, BLS.mul(Q, SK.to(Fr)));
  const eh = BLS.hashToFr(e.serialize());
  //Algorithm 3)
  const sh = BLS.sub(c, eh);

  const result = new SecretKey();
  result.deserialize(sh.serialize());
  return result;
}

class ThresherTypeGuards {
  public static memberIsHexString(
    members:
      | IMember<HexString, HexString>[]
      | IMember<Buffer, Buffer>[]
      | IMember<Uint8Array, Uint8Array>[]
      | IMember<Id, PublicKey>[]
      | IMember<unknown, unknown>[],
  ): members is IMember<HexString, HexString>[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => typeof item.id !== "string")) {
      return false;
    }
    return true;
  }

  public static memberIsBuffer(
    members:
      | IMember<HexString, HexString>[]
      | IMember<Buffer, Buffer>[]
      | IMember<Uint8Array, Uint8Array>[]
      | IMember<Id, PublicKey>[]
      | IMember<unknown, unknown>[],
  ): members is IMember<Buffer, Buffer>[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item.id instanceof Buffer))) {
      return false;
    }
    return true;
  }

  public static memberIsUint8Array(
    members:
      | IMember<HexString, HexString>[]
      | IMember<Buffer, Buffer>[]
      | IMember<Uint8Array, Uint8Array>[]
      | IMember<Id, PublicKey>[]
      | IMember<unknown, unknown>[],
  ): members is IMember<Uint8Array, Uint8Array>[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item.id instanceof Uint8Array))) {
      return false;
    }
    return true;
  }

  public static memberIsNative(
    members:
      | IMember<HexString, HexString>[]
      | IMember<Buffer, Buffer>[]
      | IMember<Uint8Array, Uint8Array>[]
      | IMember<Id, PublicKey>[]
      | IMember<unknown, unknown>[],
  ): members is IMember<Id, PublicKey>[] {
    if (!Array.isArray(members)) {
      return false;
    }
    if (members.some((item) => !(item.id instanceof Id))) {
      return false;
    }
    return true;
  }

  public static contributionIsHexString(
    contribution:
      | IContribution<HexString, HexString>
      | IContribution<Buffer, Buffer>
      | IContribution<Uint8Array, Uint8Array>
      | IContribution<unknown, unknown>,
  ): contribution is IContribution<HexString, HexString> {
    if (contribution.pg.some((item) => typeof item !== "string")) {
      return false;
    }
    return true;
  }

  public static contributionIsBuffer(
    contribution:
      | IContribution<HexString, HexString>
      | IContribution<Buffer, Buffer>
      | IContribution<Uint8Array, Uint8Array>
      | IContribution<unknown, unknown>,
  ): contribution is IContribution<Buffer, Buffer> {
    if (contribution.pg.some((item) => !(item instanceof Buffer))) {
      return false;
    }
    return true;
  }

  public static contributionIsUint8Array(
    contribution:
      | IContribution<HexString, HexString>
      | IContribution<Buffer, Buffer>
      | IContribution<Uint8Array, Uint8Array>
      | IContribution<unknown, unknown>,
  ): contribution is IContribution<Uint8Array, Uint8Array> {
    if (contribution.pg.some((item) => !(item instanceof Uint8Array))) {
      return false;
    }
    return true;
  }

  public static receivedContributionIsHexString(
    receivedContributions:
      | IReceivedContribution<HexString, HexString>[]
      | IReceivedContribution<Buffer, Buffer>[]
      | IReceivedContribution<Uint8Array, Uint8Array>[]
      | IReceivedContribution<Id, PublicKey>[]
      | IReceivedContribution<unknown, unknown>[],
  ): receivedContributions is IReceivedContribution<HexString, HexString>[] {
    if (!Array.isArray(receivedContributions)) {
      return false;
    }
    if (
      receivedContributions.some((item) => typeof item.senderId !== "string")
    ) {
      return false;
    }
    return true;
  }

  public static receivedContributionIsBuffer(
    receivedContributions:
      | IReceivedContribution<HexString, HexString>[]
      | IReceivedContribution<Buffer, Buffer>[]
      | IReceivedContribution<Uint8Array, Uint8Array>[]
      | IReceivedContribution<Id, PublicKey>[]
      | IReceivedContribution<unknown, unknown>[],
  ): receivedContributions is IReceivedContribution<Buffer, Buffer>[] {
    if (!Array.isArray(receivedContributions)) {
      return false;
    }
    if (
      receivedContributions.some((item) => !(item.senderId instanceof Buffer))
    ) {
      return false;
    }
    return true;
  }

  public static receivedContributionIsUint8Array(
    receivedContributions:
      | IReceivedContribution<HexString, HexString>[]
      | IReceivedContribution<Buffer, Buffer>[]
      | IReceivedContribution<Uint8Array, Uint8Array>[]
      | IReceivedContribution<Id, PublicKey>[]
      | IReceivedContribution<unknown, unknown>[],
  ): receivedContributions is IReceivedContribution<Uint8Array, Uint8Array>[] {
    if (!Array.isArray(receivedContributions)) {
      return false;
    }
    if (
      receivedContributions.some(
        (item) => !(item.senderId instanceof Uint8Array),
      )
    ) {
      return false;
    }
    return true;
  }

  public static receivedContributionIsNative(
    receivedContributions:
      | IReceivedContribution<HexString, HexString>[]
      | IReceivedContribution<Buffer, Buffer>[]
      | IReceivedContribution<Uint8Array, Uint8Array>[]
      | IReceivedContribution<Id, PublicKey>[]
      | IReceivedContribution<unknown, unknown>[],
  ): receivedContributions is IReceivedContribution<Id, PublicKey>[] {
    if (!Array.isArray(receivedContributions)) {
      return false;
    }
    if (receivedContributions.some((item) => !(item.senderId instanceof Id))) {
      return false;
    }
    return true;
  }

  public static thresholdKeyIsHexString(
    thresholdKey:
      | IThresholdKey<HexString, HexString, HexString>
      | IThresholdKey<Buffer, Buffer, Buffer>
      | IThresholdKey<Uint8Array, Uint8Array, Uint8Array>
      | IThresholdKey<unknown, unknown, unknown>,
  ): thresholdKey is IThresholdKey<HexString, HexString, HexString> {
    if (typeof thresholdKey.ph !== "string") {
      return false;
    }
    return true;
  }

  public static thresholdKeyIsBuffer(
    thresholdKey:
      | IThresholdKey<HexString, HexString, HexString>
      | IThresholdKey<Buffer, Buffer, Buffer>
      | IThresholdKey<Uint8Array, Uint8Array, Uint8Array>
      | IThresholdKey<unknown, unknown, unknown>,
  ): thresholdKey is IThresholdKey<Buffer, Buffer, Buffer> {
    if (thresholdKey.ph instanceof Buffer) {
      return false;
    }
    return true;
  }

  public static thresholdKeyIsUint8Array(
    thresholdKey:
      | IThresholdKey<HexString, HexString, HexString>
      | IThresholdKey<Buffer, Buffer, Buffer>
      | IThresholdKey<Uint8Array, Uint8Array, Uint8Array>
      | IThresholdKey<unknown, unknown, unknown>,
  ): thresholdKey is IThresholdKey<Uint8Array, Uint8Array, Uint8Array> {
    if (thresholdKey.ph instanceof Uint8Array) {
      return false;
    }
    return true;
  }
}

export class Thresher {
  private static calculateContributionInternal(
    threshold: number,
    members: IMember<Id, PublicKey>[],
    oldSH?: SecretKey,
  ): IContribution<Id, PublicKey> {
    const helperG = BLS.isDefault()
      ? BLS.GetGeneratorOfPublicKey().to(G2)
      : BLS.GetGeneratorOfPublicKey().to(G1);
    const SG: SecretKey[] = [];
    const PG: PublicKey[] = [];
    const ESH: IESH<Id, PublicKey>[] = [];
    if (oldSH) {
      const SG_j = oldSH;
      SG.push(SG_j);
      PG.push(SG_j.getPublicKey());
    }
    for (let i = 0 + (oldSH ? 1 : 0); i < threshold; i++) {
      //Algorithm 1)
      const SG_j = new SecretKey();
      SG_j.setByCSPRNG();
      SG.push(SG_j);
      //Algorithm 2)
      PG.push(SG_j.getPublicKey());
    }
    for (let i = 0; i < members.length; i++) {
      const id = members[i].id;
      //Algorithm 3)
      const SH_k = new SecretKey();
      SH_k.share(SG, id);
      //Algorithm 4)
      const ESH_k = BLS.isDefault()
        ? PVSHEncodeG2(id, members[i].pm, SH_k, helperG as G2)
        : PVSHEncodeG1(id, members[i].pm, SH_k, helperG as G1);
      ESH.push({
        receiverId: members[i].id,
        receiverPK: members[i].pm,
        esh: ESH_k,
      });
    }
    //Clean all secret data
    for (const SG_j of SG) {
      SG_j.clear();
    }
    // SG.forEach((SG_j) => SG_j.clear());
    //Algorithm 5)
    return { pg: PG, esh: ESH };
  }

  private static calculateSharedKeysInternal(
    shares: IReceivedContribution<Id, PublicKey>[],
    meID: Id,
    meSK: SecretKey,
  ): IThresholdKey<Id, SecretKey, PublicKey> {
    //
    const mePK = meSK.getPublicKey();
    const helperG = BLS.isDefault()
      ? BLS.GetGeneratorOfPublicKey().to(G2)
      : BLS.GetGeneratorOfPublicKey().to(G1);

    const errors: { senderId: Id | null; receiverId: Id; reason: string }[] =
      [];

    const PHForAll: {
      ID: Id; //Receiver ID
      SH: SecretKey; //Recovered Secret Share
      SHk: SecretKey[]; //Received Secret Share, it contains only if the Receiver can decode...
      PH: PublicKey; //Recovered Public key for Receiver ID
      PHk: PublicKey[]; //Received Public Share
      SenderIds: Id[]; //Sender IDs of the the Shares (SHk and PHk)
    }[] = [];

    const PG = new PublicKey();
    PG.clear();

    // const SHme = new bls.SecretKey();
    for (let i = 0; i < shares.length; i++) {
      const shareItem = shares[i];
      const senderId = shareItem.senderId;
      const PGi = shareItem.contribution.pg;
      // const PHi: bls.PublicKeyType[] = [];
      const ESHi = shareItem.contribution.esh;
      for (let k = 0; k < ESHi.length; k++) {
        const ESHik = ESHi[k];
        //Algorithm 1)
        const IDik = ESHik.receiverId; //Receiver ID
        const PKik = ESHik.receiverPK; //Receiver PK, akinek generáltam
        const PHik = new PublicKey();
        PHik.share(PGi, IDik);
        //Algorithm 2)
        const reason = BLS.isDefault()
          ? PVSHVerifyG2(IDik, PKik, PHik, ESHik.esh, helperG as G2)
          : PVSHVerifyG1(IDik, PKik, PHik, ESHik.esh, helperG as G1);
        if (reason) {
          errors.push({
            senderId: shareItem.senderId,
            receiverId: ESHik.receiverId,
            reason: reason,
          });
        }
        if (errors.length > 0) {
          continue;
        }
        // Algorithm 6)
        let PHItem = PHForAll.find((item) => item.ID.isEqual(ESHik.receiverId));
        if (!PHItem) {
          PHItem = {
            ID: ESHik.receiverId,
            SH: new SecretKey(),
            SHk: [],
            PH: new PublicKey(),
            PHk: [],
            SenderIds: [],
          };
          PHForAll.push(PHItem);
        }
        PHItem.PHk.push(PHik);
        PHItem.SenderIds.push(senderId);
        if (ESHik.receiverId.isEqual(meID)) {
          //azaz ha nekem szánták
          //Algorithm 3)
          const SHik = BLS.isDefault()
            ? PVSHDecodeG2(IDik, mePK, meSK, ESHik.esh)
            : PVSHDecodeG1(IDik, mePK, meSK, ESHik.esh);
          //Algorithm 4)
          PHItem.SHk.push(SHik);
        }
      }
    }

    if (errors.length > 0) {
      return {
        id: new Id(),
        sh: new SecretKey(),
        ph: new PublicKey(),
        phs: PHForAll.map((item) => {
          return { id: item.ID, ph: item.PH };
        }),
        pg: new PublicKey(),
        errors: errors,
      };
    }

    for (let i = 0; i < PHForAll.length; i++) {
      const PHItem = PHForAll[i];
      PHItem.PH.recover(PHItem.PHk, PHItem.SenderIds);
      if (PHItem.SHk.length > 0) {
        PHItem.SH.recover(PHItem.SHk, PHItem.SenderIds);
        //Algorithm 5)
        if (!PHItem.SH.getPublicKey().isEqual(PHItem.PH)) {
          errors.push({
            senderId: null,
            receiverId: PHItem.ID,
            reason: "INVALID_SH_PH_FOR_ME",
          });
        }
      }
    }
    PG.recover(
      PHForAll.map((item) => item.PH),
      PHForAll.map((item) => item.ID),
    );

    const mePH = PHForAll.find((item) => item.ID.isEqual(meID));
    const result = {
      id: mePH ? meID : new Id(),
      sh: mePH?.SH ?? new SecretKey(),
      ph: mePH?.PH ?? new PublicKey(),
      phs: PHForAll.map((item) => {
        return { id: item.ID, ph: item.PH };
      }),
      pg: PG,
      errors: errors,
    };
    return result;
  }

  public static calculateContribution(
    threshold: number,
    members: IMember<HexString, HexString>[],
    oldSH?: HexString,
  ): IContribution<Id, PublicKey>;
  public static calculateContribution(
    threshold: number,
    members: IMember<Buffer, Buffer>[],
    oldSH?: Buffer,
  ): IContribution<Id, PublicKey>;
  public static calculateContribution(
    threshold: number,
    members: IMember<Uint8Array, Uint8Array>[],
    oldSH?: Uint8Array,
  ): IContribution<Id, PublicKey>;
  public static calculateContribution(
    threshold: number,
    members: IMember<Id, PublicKey>[],
    oldSH?: SecretKey,
  ): IContribution<Id, PublicKey>;
  public static calculateContribution(
    threshold: number,
    members: IMember<unknown, unknown>[],
    oldSH?: unknown,
  ): IContribution<Id, PublicKey> {
    if (ThresherTypeGuards.memberIsHexString(members)) {
      const membersTemp = members.map((item) => {
        return {
          id: BLS.deserializeHexStrToId(item.id),
          pm: BLS.deserializeHexStrToPublicKey(item.pm),
        };
      });
      const oldSHTemp = oldSH
        ? BLS.deserializeHexStrToSecretKey(oldSH as HexString)
        : undefined;
      return Thresher.calculateContributionInternal(
        threshold,
        membersTemp,
        oldSHTemp,
      );
    }
    if (ThresherTypeGuards.memberIsBuffer(members)) {
      const membersTemp = members.map((item) => {
        const id = new Id();
        id.deserialize(new Uint8Array(item.id));
        const pm = new PublicKey();
        pm.deserialize(new Uint8Array(item.pm));
        return { id: id, pm: pm };
      });
      let oldSHTemp: SecretKey | undefined = undefined;
      if (oldSH) {
        oldSHTemp = new SecretKey();
        oldSHTemp.deserialize(new Uint8Array(oldSH as Buffer));
      }
      return Thresher.calculateContributionInternal(
        threshold,
        membersTemp,
        oldSHTemp,
      );
    }
    if (ThresherTypeGuards.memberIsUint8Array(members)) {
      const membersTemp = members.map((item) => {
        const id = new Id();
        id.deserialize(item.id);
        const pm = new PublicKey();
        pm.deserialize(item.pm);
        return { id: id, pm: pm };
      });
      let oldSHTemp: SecretKey | undefined = undefined;
      if (oldSH) {
        oldSHTemp = new SecretKey();
        oldSHTemp.deserialize(oldSH as Uint8Array);
      }
      return Thresher.calculateContributionInternal(
        threshold,
        membersTemp,
        oldSHTemp,
      );
    }
    if (ThresherTypeGuards.memberIsNative(members)) {
      return Thresher.calculateContributionInternal(
        threshold,
        members,
        oldSH as SecretKey,
      );
    }
    throw new Error("generateContributionTTT:mismatch type");
  }

  public static contributionToHex(
    contribution: IContribution<Id, PublicKey>,
  ): IContribution<HexString, HexString> {
    //
    const result: IContribution<HexString, HexString> = {
      pg: contribution.pg.map((item) => item.serializeToHexStr()),
      esh: contribution.esh.map((item) => {
        return {
          receiverId: item.receiverId.serializeToHexStr(),
          receiverPK: item.receiverPK.serializeToHexStr(),
          esh: item.esh,
        };
      }),
    };
    return result;
  }

  public static contributionToBuffer(
    contribution: IContribution<Id, PublicKey>,
  ): IContribution<Buffer, Buffer> {
    const result: IContribution<Buffer, Buffer> = {
      pg: contribution.pg.map((item) => Buffer.from(item.serialize())),
      esh: contribution.esh.map((item) => {
        return {
          receiverId: Buffer.from(item.receiverId.serialize()),
          receiverPK: Buffer.from(item.receiverPK.serialize()),
          esh: item.esh,
        };
      }),
    };
    return result;
  }

  public static contributionToUint8Array(
    contribution: IContribution<Id, PublicKey>,
  ): IContribution<Uint8Array, Uint8Array> {
    const result: IContribution<Uint8Array, Uint8Array> = {
      pg: contribution.pg.map((item) => item.serialize()),
      esh: contribution.esh.map((item) => {
        return {
          receiverId: item.receiverId.serialize(),
          receiverPK: item.receiverPK.serialize(),
          esh: item.esh,
        };
      }),
    };
    return result;
  }

  public static contributionFrom(
    contribution: IContribution<HexString, HexString>,
  ): IContribution<Id, PublicKey>;
  public static contributionFrom(
    contribution: IContribution<Buffer, Buffer>,
  ): IContribution<Id, PublicKey>;
  public static contributionFrom(
    contribution: IContribution<Uint8Array, Uint8Array>,
  ): IContribution<Id, PublicKey>;
  public static contributionFrom(
    contribution: IContribution<unknown, unknown>,
  ): IContribution<Id, PublicKey> {
    if (ThresherTypeGuards.contributionIsHexString(contribution)) {
      const result: IContribution<Id, PublicKey> = {
        pg: contribution.pg.map((item) =>
          BLS.deserializeHexStrToPublicKey(item),
        ),
        esh: contribution.esh.map((item) => {
          return {
            receiverId: BLS.deserializeHexStrToId(item.receiverId),
            receiverPK: BLS.deserializeHexStrToPublicKey(item.receiverPK),
            esh: item.esh,
          };
        }),
      };
      return result;
    }
    if (ThresherTypeGuards.contributionIsBuffer(contribution)) {
      const result: IContribution<Id, PublicKey> = {
        pg: contribution.pg.map((item) => {
          const pg = new PublicKey();
          pg.deserialize(new Uint8Array(item));
          return pg;
        }),
        esh: contribution.esh.map((item) => {
          const id = new Id();
          id.deserialize(new Uint8Array(item.receiverId));
          const pk = new PublicKey();
          pk.deserialize(new Uint8Array(item.receiverPK));
          return {
            receiverId: id,
            receiverPK: pk,
            esh: item.esh,
          };
        }),
      };
      return result;
    }
    if (ThresherTypeGuards.contributionIsUint8Array(contribution)) {
      const result: IContribution<Id, PublicKey> = {
        pg: contribution.pg.map((item) => {
          const pg = new PublicKey();
          pg.deserialize(item);
          return pg;
        }),
        esh: contribution.esh.map((item) => {
          const id = new Id();
          id.deserialize(item.receiverId);
          const pk = new PublicKey();
          pk.deserialize(item.receiverPK);
          return {
            receiverId: id,
            receiverPK: pk,
            esh: item.esh,
          };
        }),
      };
      return result;
    }
    throw new Error("generateContributionTTT:mismatch type");
  }

  public static calculateThresholdKeys(
    receivedContributions: IReceivedContribution<HexString, HexString>[],
    meID: HexString,
    meSK: HexString,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static calculateThresholdKeys(
    receivedContributions: IReceivedContribution<Buffer, Buffer>[],
    meID: Buffer,
    meSK: Buffer,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static calculateThresholdKeys(
    receivedContributions: IReceivedContribution<Uint8Array, Uint8Array>[],
    meID: Uint8Array,
    meSK: Uint8Array,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static calculateThresholdKeys(
    receivedContributions: IReceivedContribution<Id, PublicKey>[],
    meID: Id,
    meSK: SecretKey,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static calculateThresholdKeys(
    receivedContributions: IReceivedContribution<unknown, unknown>[],
    meID: unknown,
    meSK: unknown,
  ): IThresholdKey<Id, SecretKey, PublicKey> {
    if (
      ThresherTypeGuards.receivedContributionIsHexString(
        receivedContributions,
      ) &&
      typeof meID === "string" &&
      typeof meSK === "string"
    ) {
      const receivedContributionTemp = receivedContributions.map((item) => {
        const id = BLS.deserializeHexStrToId(item.senderId);
        const contribution = Thresher.contributionFrom(item.contribution);
        return { senderId: id, contribution: contribution };
      });
      const meIDTemp = BLS.deserializeHexStrToId(meID);
      const meSKTemp = BLS.deserializeHexStrToSecretKey(meSK);
      return Thresher.calculateSharedKeysInternal(
        receivedContributionTemp,
        meIDTemp,
        meSKTemp,
      );
    }
    if (
      ThresherTypeGuards.receivedContributionIsBuffer(receivedContributions) &&
      meID instanceof Buffer &&
      meSK instanceof Buffer
    ) {
      const receivedContributionTemp = receivedContributions.map((item) => {
        const id = new Id();
        id.deserialize(new Uint8Array(item.senderId));
        const contribution = Thresher.contributionFrom(item.contribution);
        return { senderId: id, contribution: contribution };
      });
      const meIDTemp = new Id();
      meIDTemp.deserialize(new Uint8Array(meID));
      const meSKTemp = new SecretKey();
      meSKTemp.deserialize(new Uint8Array(meSK));
      return Thresher.calculateSharedKeysInternal(
        receivedContributionTemp,
        meIDTemp,
        meSKTemp,
      );
    }
    if (
      ThresherTypeGuards.receivedContributionIsUint8Array(
        receivedContributions,
      ) &&
      meID instanceof Uint8Array &&
      meSK instanceof Uint8Array
    ) {
      const receivedContributionTemp = receivedContributions.map((item) => {
        const id = new Id();
        id.deserialize(item.senderId);
        const contribution = Thresher.contributionFrom(item.contribution);
        return { senderId: id, contribution: contribution };
      });
      const meIDTemp = new Id();
      meIDTemp.deserialize(meID);
      const meSKTemp = new SecretKey();
      meSKTemp.deserialize(meSK);
      return Thresher.calculateSharedKeysInternal(
        receivedContributionTemp,
        meIDTemp,
        meSKTemp,
      );
    }
    if (
      ThresherTypeGuards.receivedContributionIsNative(receivedContributions) &&
      meID instanceof Id &&
      meSK instanceof SecretKey
    ) {
      return Thresher.calculateSharedKeysInternal(
        receivedContributions,
        meID,
        meSK,
      );
    }
    throw new Error("generateContributionTTT:mismatch type");
  }

  public static thresholdKeyToHex(
    sharedKey: IThresholdKey<Id, SecretKey, PublicKey>,
  ): IThresholdKey<HexString, HexString, HexString> {
    const result: IThresholdKey<HexString, HexString, HexString> = {
      id: sharedKey.id.serializeToHexStr(),
      sh: sharedKey.sh.serializeToHexStr(),
      ph: sharedKey.ph.serializeToHexStr(),
      phs: sharedKey.phs.map((item) => {
        return {
          id: item.id.serializeToHexStr(),
          ph: item.ph.serializeToHexStr(),
        };
      }),
      pg: sharedKey.pg.serializeToHexStr(),
      errors: sharedKey.errors.map((item) => {
        return {
          senderId: item.senderId ? item.senderId.serializeToHexStr() : null,
          receiverId: item.receiverId.serializeToHexStr(),
          reason: item.reason,
        };
      }),
    };
    return result;
  }

  public static thresholdKeyToBuffer(
    sharedKey: IThresholdKey<Id, SecretKey, PublicKey>,
  ): IThresholdKey<Buffer, Buffer, Buffer> {
    const result: IThresholdKey<Buffer, Buffer, Buffer> = {
      id: Buffer.from(sharedKey.id.serialize()),
      sh: Buffer.from(sharedKey.sh.serialize()),
      ph: Buffer.from(sharedKey.ph.serialize()),
      phs: sharedKey.phs.map((item) => {
        return {
          id: Buffer.from(item.id.serialize()),
          ph: Buffer.from(item.ph.serialize()),
        };
      }),
      pg: Buffer.from(sharedKey.pg.serialize()),
      errors: sharedKey.errors.map((item) => {
        return {
          senderId: item.senderId
            ? Buffer.from(item.senderId.serialize())
            : null,
          receiverId: Buffer.from(item.receiverId.serialize()),
          reason: item.reason,
        };
      }),
    };
    return result;
  }

  public static thresholdKeyToUint8Array(
    sharedKey: IThresholdKey<Id, SecretKey, PublicKey>,
  ): IThresholdKey<Uint8Array, Uint8Array, Uint8Array> {
    const result: IThresholdKey<Uint8Array, Uint8Array, Uint8Array> = {
      id: sharedKey.id.serialize(),
      sh: sharedKey.sh.serialize(),
      ph: sharedKey.ph.serialize(),
      phs: sharedKey.phs.map((item) => {
        return {
          id: item.id.serialize(),
          ph: item.ph.serialize(),
        };
      }),
      pg: sharedKey.pg.serialize(),
      errors: sharedKey.errors.map((item) => {
        return {
          senderId: item.senderId ? item.senderId.serialize() : null,
          receiverId: item.receiverId.serialize(),
          reason: item.reason,
        };
      }),
    };
    return result;
  }

  public static thresholdKeyFrom(
    thresholdKey: IThresholdKey<HexString, HexString, HexString>,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static thresholdKeyFrom(
    thresholdKey: IThresholdKey<Buffer, Buffer, Buffer>,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static thresholdKeyFrom(
    thresholdKey: IThresholdKey<Uint8Array, Uint8Array, Uint8Array>,
  ): IThresholdKey<Id, SecretKey, PublicKey>;
  public static thresholdKeyFrom(
    thresholdKey: IThresholdKey<unknown, unknown, unknown>,
  ): IThresholdKey<Id, SecretKey, PublicKey> {
    if (ThresherTypeGuards.thresholdKeyIsHexString(thresholdKey)) {
      const result: IThresholdKey<Id, SecretKey, PublicKey> = {
        id: BLS.deserializeHexStrToId(thresholdKey.id),
        sh: BLS.deserializeHexStrToSecretKey(thresholdKey.sh),
        ph: BLS.deserializeHexStrToPublicKey(thresholdKey.ph),
        phs: thresholdKey.phs.map((item) => {
          return {
            id: BLS.deserializeHexStrToId(item.id),
            ph: BLS.deserializeHexStrToPublicKey(item.ph),
          };
        }),
        pg: BLS.deserializeHexStrToPublicKey(thresholdKey.pg),
        errors: thresholdKey.errors.map((item) => {
          return {
            senderId: item.senderId
              ? BLS.deserializeHexStrToId(item.senderId)
              : null,
            receiverId: BLS.deserializeHexStrToId(item.receiverId),
            reason: item.reason,
          };
        }),
      };
      return result;
    }
    if (ThresherTypeGuards.thresholdKeyIsBuffer(thresholdKey)) {
      const id = new Id();
      id.deserialize(new Uint8Array(thresholdKey.id));
      const sh = new SecretKey();
      sh.deserialize(new Uint8Array(thresholdKey.sh));
      const ph = new PublicKey();
      ph.deserialize(new Uint8Array(thresholdKey.ph));
      const pg = new PublicKey();
      pg.deserialize(new Uint8Array(thresholdKey.pg));
      const result: IThresholdKey<Id, SecretKey, PublicKey> = {
        id: id,
        sh: sh,
        ph: ph,
        phs: thresholdKey.phs.map((item) => {
          const idTemp = new Id();
          idTemp.deserialize(new Uint8Array(item.id));
          const phTemp = new PublicKey();
          phTemp.deserialize(new Uint8Array(item.ph));
          return { id: idTemp, ph: phTemp };
        }),
        pg: pg,
        errors: thresholdKey.errors.map((item) => {
          const senderId = new Id();
          if (item.senderId) {
            senderId.deserialize(new Uint8Array(item.senderId));
          }
          const receiverId = new Id();
          receiverId.deserialize(new Uint8Array(item.receiverId));
          return {
            senderId: item.senderId ? senderId : null,
            receiverId: receiverId,
            reason: item.reason,
          };
        }),
      };
      return result;
    }
    if (ThresherTypeGuards.thresholdKeyIsUint8Array(thresholdKey)) {
      const id = new Id();
      id.deserialize(thresholdKey.id);
      const sh = new SecretKey();
      sh.deserialize(thresholdKey.sh);
      const ph = new PublicKey();
      ph.deserialize(thresholdKey.ph);
      const pg = new PublicKey();
      pg.deserialize(thresholdKey.pg);
      const result: IThresholdKey<Id, SecretKey, PublicKey> = {
        id: id,
        sh: sh,
        ph: ph,
        phs: thresholdKey.phs.map((item) => {
          const idTemp = new Id();
          idTemp.deserialize(item.id);
          const phTemp = new PublicKey();
          phTemp.deserialize(item.ph);
          return { id: idTemp, ph: phTemp };
        }),
        pg: pg,
        errors: thresholdKey.errors.map((item) => {
          const senderId = new Id();
          if (item.senderId) {
            senderId.deserialize(item.senderId);
          }
          const receiverId = new Id();
          receiverId.deserialize(item.receiverId);
          return {
            senderId: item.senderId ? senderId : null,
            receiverId: receiverId,
            reason: item.reason,
          };
        }),
      };
      return result;
    }
    throw new Error("generateContributionTTT:mismatch type");
  }
}
