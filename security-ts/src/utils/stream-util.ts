import { Readable } from "stream";

export const drainStreamToBuffer = async (
  readable: Readable,
): Promise<Buffer> =>
  new Promise((resolve) => {
    const collector: Buffer[] = [];

    readable.on("end", () => resolve(Buffer.concat(collector)));
    readable.on("data", (chunk: Buffer | string) => {
      collector.push(chunk instanceof Buffer ? chunk : Buffer.from(chunk));
    });
  });
