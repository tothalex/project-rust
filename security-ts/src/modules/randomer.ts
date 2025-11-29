import { randomBytes } from "crypto";

export class Randomer {
  static getRandomInt(max: number): number {
    return Math.floor(Math.random() * Math.floor(max));
  }

  static getTrueRandom(size: number): Buffer {
    // TODO Initialize Random numbers from random.org:
    // https://www.random.org/cgi-bin/randbyte?nbytes=16384&format=f
    // fromat can be "h" for hexa, then must remove spaces
    // if success then get random numbers from bytes
    // Cron job: Initialize Random numbers from random.org in every 12 hours
    // If could not initialize then use _crypto.randomBytes
    return randomBytes(size);
  }

  static randomBytes(size: number, useTrueRandom = false): Buffer {
    let result = randomBytes(size);

    if (useTrueRandom) {
      const index = Randomer.getRandomInt(size);
      result = Buffer.concat(
        [
          Buffer.from(result, 0, index - 1),
          Buffer.from(Randomer.getTrueRandom(1)),
          Buffer.from(result, index, size - index),
        ],
        size,
      );
    }

    return result;
  }
}
