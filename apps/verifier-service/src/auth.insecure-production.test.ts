import { strict as assert } from "node:assert";

process.env.NODE_ENV = "production";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";
process.env.TRUST_PROXY = "true";
process.env.ISSUER_SERVICE_BASE_URL = "http://issuer.test";
process.env.PSEUDONYMIZER_PEPPER = "test-pepper";
delete process.env.SERVICE_JWT_SECRET;

const run = async () => {
  try {
    const { config } = await import("./config.js");
    config.TRUST_PROXY = true;
    const { buildServer } = await import("./server.js");
    buildServer();
    assert.fail("Expected buildServer to throw in production insecure mode");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert.equal(message, "insecure_dev_auth_not_allowed");
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
