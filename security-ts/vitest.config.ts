import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    globals: true,
  },
  resolve: {
    alias: {
      "jose-node-cjs-runtime": path.resolve(
        __dirname,
        "node_modules/jose-node-cjs-runtime/dist/node/cjs/index.js"
      ),
    },
  },
});
