import { strict as assert } from "node:assert";

process.env.NODE_ENV = "test";
process.env.ANCHOR_WORKER_POLL_MS = "10";
process.env.ISSUER_BASE_URL = "http://issuer.test";

const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const run = async () => {
  const { startAnchorWorker } = await import("./anchorWorker.js");
  let calls = 0;
  const stop = startAnchorWorker({
    process: async () => {
      calls += 1;
      await wait(50);
    }
  });
  await wait(30);
  stop();
  assert.equal(calls, 1);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
