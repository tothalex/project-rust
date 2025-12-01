import { bench, describe } from "vitest";
import { VirtualDevice } from "./virtual-device";
import { Hiver } from "../modules/hiver";
import type { IActorContract } from "../types/common";

// Initialize BLS before running benchmarks
await Hiver.init();

describe("VirtualDevice Performance Benchmarks", () => {
  bench("new VirtualDevice()", () => {
    new VirtualDevice("Benchmark Device");
  });

  bench("generateDeviceStorage (via constructor)", () => {
    new VirtualDevice("Test Device");
  });
});

describe("Contribution Generation Benchmarks", () => {
  // Create a mock actor contract helper
  const createMockActorContract = (numMembers: number): IActorContract => {
    const members = Array.from({ length: numMembers }, () => {
      const keys = Hiver.generateKeyPairHex();
      const id = Hiver.generateId().serializeToHexStr();
      return { id, pm: keys.publicKey };
    });

    const threshold = Math.ceil((numMembers + 1) / 2);

    return {
      id: "mock-contract-id",
      threshold,
      newMembers: members,
      contributions: [],
      actorShare: {
        shareCode: "MOCK_SHARE",
        subjectActorId: "mock-subject",
        hatId: "mock-hat",
        fromActorId: "mock-from",
        toActorId: "mock-to",
        ownerActorId: "mock-owner",
        subjectActorType: "DEVICE",
        roleCode: "DEVICEREG",
      },
    };
  };

  bench("generateContribution - 2 members", () => {
    const device = new VirtualDevice("Benchmark Device");
    const contract = createMockActorContract(2);
    device.generateContribution(contract);
  });

  bench("generateContribution - 3 members", () => {
    const device = new VirtualDevice("Benchmark Device");
    const contract = createMockActorContract(3);
    device.generateContribution(contract);
  });

  bench("generateContribution - 5 members", () => {
    const device = new VirtualDevice("Benchmark Device");
    const contract = createMockActorContract(5);
    device.generateContribution(contract);
  });

  bench("generateContribution - 10 members", () => {
    const device = new VirtualDevice("Benchmark Device");
    const contract = createMockActorContract(10);
    device.generateContribution(contract);
  });
});

describe("Key Generation Benchmarks", () => {
  bench("Hiver.generateKeyPairHex()", () => {
    Hiver.generateKeyPairHex();
  });

  bench("Hiver.generateId()", () => {
    Hiver.generateId();
  });
});
