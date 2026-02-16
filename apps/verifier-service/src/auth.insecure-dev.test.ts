import { strict as assert } from "node:assert";

process.env.NODE_ENV = "development";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";
process.env.SERVICE_BIND_ADDRESS = "127.0.0.1";
process.env.ISSUER_SERVICE_BASE_URL = "http://issuer.test";
process.env.POLICY_SERVICE_BASE_URL = "http://policy.test";
process.env.PSEUDONYMIZER_PEPPER = "test-pepper";
delete process.env.SERVICE_JWT_SECRET;

const run = async () => {
  const { buildServer } = await import("./server.js");
  const app = buildServer();
  assert.ok(app);
  await app.close();
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
