import assert from "node:assert/strict";

const setupEnv = () => {
  process.env.NODE_ENV = "development";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.DID_SERVICE_BASE_URL = "http://localhost:3001";
  process.env.ISSUER_SERVICE_BASE_URL = "http://localhost:3002";
  process.env.VERIFIER_SERVICE_BASE_URL = "http://localhost:3003";
  process.env.DATABASE_URL =
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
  process.env.SERVICE_JWT_SECRET = "test-secret-12345678901234567890123456789012";
  process.env.SERVICE_JWT_SECRET_DID = "test-secret-12345678901234567890123456789012-did";
  process.env.SERVICE_JWT_SECRET_ISSUER = "test-secret-12345678901234567890123456789012-issuer";
  process.env.SERVICE_JWT_SECRET_VERIFIER = "test-secret-12345678901234567890123456789012-verifier";
  process.env.ALLOW_LEGACY_SERVICE_JWT_SECRET = "false";
  process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";
  process.env.PSEUDONYMIZER_PEPPER = "pepper-test-123456";
  process.env.USER_PAYS_HANDOFF_SECRET = "user-pays-handoff-secret-12345678901234567890";
  process.env.CONTRACT_E2E_ENABLED = "true";
  process.env.CONTRACT_E2E_ADMIN_TOKEN = "contract-e2e-admin-token";
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

const buildApp = async (allowlist) => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  return buildServer({
    configOverride: {
      ...config,
      CONTRACT_E2E_ENABLED: true,
      CONTRACT_E2E_ADMIN_TOKEN: "contract-e2e-admin-token",
      CONTRACT_E2E_IP_ALLOWLIST: allowlist
    },
    fetchImpl
  });
};

const revoke = async (app, remoteAddress) =>
  app.inject({
    method: "POST",
    url: "/v1/onboard/revoke",
    remoteAddress,
    headers: {
      "x-device-id": "device-test-1",
      "x-contract-e2e-token": "contract-e2e-admin-token"
    },
    payload: { eventId: "evt-test-123" }
  });

await run("allows IPv4 CIDR match", async () => {
  const app = await buildApp(["203.0.113.0/24"]);
  const response = await revoke(app, "203.0.113.9");
  assert.equal(response.statusCode, 200);
  await app.close();
});

await run("denies IPv4 CIDR non-match", async () => {
  const app = await buildApp(["203.0.113.0/24"]);
  const response = await revoke(app, "203.0.114.9");
  assert.equal(response.statusCode, 403);
  await app.close();
});

await run("allows IPv4-mapped IPv6 in IPv4 CIDR", async () => {
  const app = await buildApp(["203.0.113.0/24"]);
  const response = await revoke(app, "::ffff:203.0.113.4");
  assert.equal(response.statusCode, 200);
  await app.close();
});

await run("allows IPv6 CIDR match", async () => {
  const app = await buildApp(["2001:db8::/32"]);
  const response = await revoke(app, "2001:db8::1");
  assert.equal(response.statusCode, 200);
  await app.close();
});

await run("denies IPv6 CIDR non-match", async () => {
  const app = await buildApp(["2001:db8::/32"]);
  const response = await revoke(app, "2001:db9::1");
  assert.equal(response.statusCode, 403);
  await app.close();
});

await run("prefix edge cases (/0 and /32)", async () => {
  const app = await buildApp(["0.0.0.0/0", "203.0.113.9/32"]);
  const response = await revoke(app, "203.0.113.9");
  assert.equal(response.statusCode, 200);
  await app.close();
});

await run("prefix edge cases (/128)", async () => {
  const app = await buildApp(["2001:db8::1/128"]);
  const response = await revoke(app, "2001:db8::1");
  assert.equal(response.statusCode, 200);
  await app.close();
});
