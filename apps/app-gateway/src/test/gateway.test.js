/* global Response, console, process */

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

await run("sponsored DID create request returns 410 Gone", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config, GATEWAY_ALLOWED_VCTS: ["cuncta.age_over_18"] }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/request",
    headers: { "x-device-id": "device-test-1" },
    payload: {
      network: "testnet",
      publicKeyMultibase: "z6Mkf5rGMoatqSjLf5fH2h6F4i2kUXqF2z7ABC",
      options: {}
    }
  });
  assert.equal(response.statusCode, 410);
  const body = response.json();
  assert.equal(body.error, "sponsored_onboarding_not_supported");
  await app.close();
});

await run("sponsored DID create submit returns 410 Gone", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config, GATEWAY_ALLOWED_VCTS: ["cuncta.age_over_18"] }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers: { "x-device-id": "device-test-2" },
    payload: { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" }
  });
  assert.equal(response.statusCode, 410);
  const body = response.json();
  assert.equal(body.error, "sponsored_onboarding_not_supported");
  await app.close();
});

await run("sponsored onboard issue returns 410 Gone", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const app = buildServer({
    configOverride: { ...config, GATEWAY_ALLOWED_VCTS: ["cuncta.age_over_18"] }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/issue",
    headers: { "x-device-id": "device-test-3" },
    payload: {
      subjectDid: "did:hedera:testnet:0.0.1",
      vct: "cuncta.marketplace.seller_good_standing",
      claims: {}
    }
  });
  assert.equal(response.statusCode, 410);
  const body = response.json();
  assert.equal(body.error, "sponsored_onboarding_not_supported");
  await app.close();
});

await run("verify proxy normalizes reasons by default", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ decision: "DENY", reasons: ["kb_jwt_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, GATEWAY_VERIFY_DEBUG_REASONS: false },
    fetchImpl
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/verify?action=marketplace.list_item",
    payload: { presentation: "x~y", nonce: "nonce-value-123", audience: "audience-value-123" }
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.decision, "DENY");
  assert.ok(body.message);
  assert.equal(body.reasons, undefined);
  await app.close();
});

await run("verify proxy includes reasons only when enabled", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ decision: "DENY", reasons: ["kb_jwt_missing"] }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, GATEWAY_VERIFY_DEBUG_REASONS: true },
    fetchImpl
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/verify?action=marketplace.list_item",
    payload: { presentation: "x~y", nonce: "nonce-value-123", audience: "audience-value-123" }
  });
  assert.equal(response.statusCode, 200);
  const body = response.json();
  assert.equal(body.decision, "DENY");
  assert.ok(Array.isArray(body.reasons));
  assert.ok(body.reasons?.includes("kb_jwt_missing"));
  await app.close();
});

await run("verify proxy debug reasons disabled in production", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  assert.throws(() => {
    buildServer({
      configOverride: {
        ...config,
        NODE_ENV: "production",
        TRUST_PROXY: true,
        GATEWAY_VERIFY_DEBUG_REASONS: true
      }
    });
  }, /gateway_verify_debug_reasons_disabled/);
});
