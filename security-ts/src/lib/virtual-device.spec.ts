import { Hiver } from "../modules/hiver";
import { VirtualDevice } from "./virtual-device";

describe("virtualDevice", () => {
  beforeAll(async () => {
    await Hiver.init();
  });

  it("should create a device", () => {
    const newDevice = new VirtualDevice("Maggie Smith");
    expect(newDevice.deviceName).toEqual("Maggie Smith");
    expect(newDevice.storage.sm).toEqual(expect.any(String));
    expect(newDevice.storage.pm).toEqual(expect.any(String));
    expect(newDevice.storage.sharedDeviceData.sm).toEqual(expect.any(String));
    expect(newDevice.storage.sharedDeviceData.pm).toEqual(expect.any(String));
  });
});
