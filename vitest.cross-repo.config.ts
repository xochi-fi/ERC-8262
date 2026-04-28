import { defineConfig } from "vitest/config";

// Config used by `make test-xochi-sdk`. Mirrors vitest.config.ts but does NOT
// exclude the cross-repo SDK tests (they require ../xochi-sdk on disk and are
// gated behind their own Makefile target).
export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["test/sdk/xochi-sdk.test.ts", "test/sdk/settlement-splitting.test.ts"],
    testTimeout: 180_000,
    hookTimeout: 120_000,
    sequence: { concurrent: false },
    fileParallelism: false,
  },
});
