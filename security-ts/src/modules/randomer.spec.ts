import { Randomer } from "./randomer";

describe("Randomer", () => {
  test("should generate different values", () => {
    const random1 = Randomer.randomBytes(32);
    const random2 = Randomer.randomBytes(32);
    expect(random1).toBeDefined();
    expect(typeof random1).toBe("object");
    expect(random1.toString("hex")).not.toBe(random2.toString("hex"));
  });
});
