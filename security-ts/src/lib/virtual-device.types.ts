import { IActorShareData } from "../types/common";
import { HexString } from "../types/utils.types";

export type VirtualDeviceStorage = {
  id: string;
  sm: string;
  pm: string;
  loginShare?: IActorShareDataDevice;
  name: string;
  osName?: string;
  osVersion?: string;
  appVersion?: number;
  createdAt?: number;
  lastLoggedIn?: number;
  sharedDeviceData: {
    id: string;
    sm: string;
    pm: string;
    actorShares: IActorShareDataDevice[];
  };
  profiles?: [];
};

export interface IActorShareDataDevice extends IActorShareData {
  actorId: HexString;
  roleCode: string;
  pg: HexString;
  sh: HexString;
  ph: HexString;
  phs: { id: HexString; ph: HexString }[];
}
