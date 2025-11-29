import { got } from "got";

import { VirtualDevice } from "./lib/virtual-device";
import { IActorContract, IOperationResponse } from "./types/common";
import { Hiver } from "./modules/hiver";
import { BLS } from "./modules/bls-helper";

const main = async () => {
  // Initialize BLS library
  await BLS.init(false);

  const baseURL = "http://localhost:3000/api";

  const device = new VirtualDevice("test device");

  const createDeviceInput = {
    name: device.storage.name,
    id: device.storage.id,
    pm: device.storage.pm,
    sharedId: device.storage.sharedDeviceData.id,
    sharedPm: device.storage.sharedDeviceData.pm,
    model: "Interactor Device",
    osName: "Other",
    osVersion: "1",
    pushToken: "pushItToTheLimit",
  };

  const operation: IOperationResponse<IActorContract> = await got
    .post(`${baseURL}/devices`, {
      json: createDeviceInput,
    })
    .json();

  if (!operation.result) {
    throw new Error("No result");
  }

  const contribution = device.generateContribution(operation.result);

  const url = `${baseURL}/actor-contracts/${operation.result.id}/contribute-device`;

  const shareCode = `DEVICEREG_${device.storage.id}`;

  const data = {
    payload: {
      contractId: operation.result.id,
      senderId: device.storage.id,
      contribution,
      // Note: This only works in dev mode (intentionally):
      deviceRegistrationToken: device.storage.sharedDeviceData.id,
    },
    initiationContext: {
      actingActorId: device.storage.id,
      hatActorId: device.storage.sharedDeviceData.id,
      shareCode: shareCode,
      roleCode: "DEVICEREG",
      ownerActorId: device.storage.sharedDeviceData.id,
      subjectActorId: device.storage.sharedDeviceData.id,
      instructionMode: {
        code: "IN_PERSON",
      },
      initiationRole: {
        code: "OWN_NAME",
      },
    },
    messageId: "random-id",
    url,
  };

  const inputOperation = {
    data,
    signature: Hiver.sign(
      data,
      "utf8",
      device.storage.sharedDeviceData.sm,
    ).serializeToHexStr(),
  };

  const contributionResponse: IOperationResponse<IActorContract> = await got
    .post(url, {
      json: inputOperation,
    })
    .json();

  const share = device.generateActorShare(
    device.storage.id,
    contributionResponse.result,
    device.storage.id,
    device.storage.sm,
  );

  console.log(share);
};

main();
