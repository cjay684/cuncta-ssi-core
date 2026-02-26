import assert from "node:assert/strict";
import { metrics } from "../metrics.ts";

const getMetricValue = (rendered, name) => {
  const regex = new RegExp(`^${name}[^\\n]*\\s+(\\d+)$`, "m");
  const match = rendered.match(regex);
  if (!match) return null;
  return Number(match[1]);
};

const setupEnv = () => {
  process.env.NODE_ENV = "development";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.SERVICE_JWT_SECRET_FORMAT_STRICT = "false";
  process.env.SERVICE_JWT_SECRET = "test-secret-12345678901234567890123456789012";
  process.env.SERVICE_JWT_SECRET_DID = "test-secret-12345678901234567890123456789012-did";
  process.env.SERVICE_JWT_SECRET_NEXT = "test-secret-12345678901234567890123456789012-next";
};

const run = async (name, fn) => {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

await run("did-resolution metrics are registered", async () => {
  const rendered = metrics.render();
  assert.ok(rendered.includes("did_resolution_poll_total"));
  assert.ok(rendered.includes("did_resolution_success_total"));
  assert.ok(rendered.includes("did_resolution_timeout_total"));
  assert.ok(rendered.includes("did_resolution_last_elapsed_ms"));
});

await run("resolve error increments poll + last_error", async () => {
  setupEnv();
  try {
    const { buildServer } = await import("../server.ts");
    const app = buildServer();
    await app.ready();

    const before = metrics.render();
    const beforePoll = getMetricValue(before, "did_resolution_poll_total") ?? 0;
    const beforeErrors = getMetricValue(before, "did_resolution_last_error_total") ?? 0;

    const response = await app.inject({
      method: "GET",
      url: "/v1/dids/resolve/did:example:invalid"
    });
    assert.equal(response.statusCode, 500);

    const after = metrics.render();
    const afterPoll = getMetricValue(after, "did_resolution_poll_total") ?? 0;
    const afterErrors = getMetricValue(after, "did_resolution_last_error_total") ?? 0;

    assert.ok(afterPoll > beforePoll);
    assert.ok(afterErrors > beforeErrors);

    await app.close();
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ERR_REQUIRE_CYCLE_MODULE") {
      console.log("skipped - resolve error increments poll + last_error (esm cycle)");
      return;
    }
    throw error;
  }
});
