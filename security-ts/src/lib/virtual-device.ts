import { Hiver } from "../modules/hiver";
import { Thresher } from "../modules/thresher";
import {
  HexString,
  IActorContract,
  IActorContractResponse,
  IContribution,
  IHatDescriptor,
  IUserResponse,
} from "../types/common";

import type {
  IActorShareDataDevice,
  VirtualDeviceStorage,
} from "./virtual-device.types";

export class VirtualDevice {
  public deviceName: string;
  public storage: VirtualDeviceStorage;
  public accessToken?: string;
  public currentProfile?: IUserResponse;
  public currentHat?: IHatDescriptor;
  public apiVersion?: string;

  constructor(
    deviceName: string = "Virtual device",
    storage?: VirtualDeviceStorage,
  ) {
    this.deviceName = deviceName;
    this.storage = storage ?? this.generateDeviceStorage();
  }

  public generateActorShare(
    actorId: HexString,
    actorContract: IActorContract | IActorContractResponse,
    id: HexString,
    sk: HexString,
  ): IActorShareDataDevice {
    const actorKeys = Thresher.thresholdKeyToHex(
      Thresher.calculateThresholdKeys(actorContract.contributions, id, sk),
    );
    if (actorKeys.errors.length > 0) {
      throw new Error("Errors found during calculating the shared key!");
    }

    return {
      actorId,
      shareCode: actorContract.actorShare.shareCode,
      subjectActorId: actorContract.actorShare.subjectActorId,
      subjectActorType: actorContract.actorShare.subjectActorType,
      hatId: actorContract.actorShare.hatId,
      fromActorId: actorContract.actorShare.fromActorId,
      roleCode: actorContract.actorShare.roleCode,
      toActorId: actorContract.actorShare.toActorId,
      ownerActorId: actorContract.actorShare.ownerActorId,
      pg: actorKeys.pg,
      sh: actorKeys.sh,
      ph: actorKeys.ph,
      phs: [...actorKeys.phs],
    };
  }

  public getShareCode(subjectId: HexString, hatId?: HexString): string {
    if (!hatId) {
      hatId = this.currentHat?.hatActorId;
    }

    return this.storage.sharedDeviceData.actorShares.find(
      (share) => share.subjectActorId === subjectId && share.hatId === hatId,
    )?.shareCode as string;
  }

  public generateContribution(
    actorContract: IActorContract | IActorContractResponse,
  ): IContribution<string, string> {
    const { threshold, newMembers } = actorContract;

    return Thresher.contributionToHex(
      Thresher.calculateContribution(threshold, newMembers),
    );
  }

  public getBearerToken(strict = true): string {
    if (!this.accessToken && strict) {
      throw new Error("Acces token is not available!");
    }

    if (!this.accessToken) {
      return "";
    }

    return `Bearer ${this.accessToken}`;
  }

  private generateDeviceStorage(): VirtualDeviceStorage {
    const deviceKeys = Hiver.generateKeyPairHex();

    const sharedDeviceKeys = Hiver.generateKeyPairHex();

    return {
      id: Hiver.generateId().serializeToHexStr(),
      sm: deviceKeys.secretKey,
      pm: deviceKeys.publicKey,
      name: this.deviceName,
      sharedDeviceData: {
        id: Hiver.generateId().serializeToHexStr(),
        sm: sharedDeviceKeys.secretKey,
        pm: sharedDeviceKeys.publicKey,
        actorShares: [],
      },
    };
  }
}
