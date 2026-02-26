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
  process.env.SPONSOR_MAX_DID_CREATES_PER_DAY = "1000";
  process.env.SPONSOR_MAX_ISSUES_PER_DAY = "1000";
  process.env.SPONSOR_KILL_SWITCH = "false";
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

const sponsorBudgetPass = {
  reserveSponsorBudget: async () => ({
    allowed: true,
    reservation: { id: "res-1", day: "2026-01-01", kind: "did_create", status: "RESERVED" }
  }),
  commitSponsorBudgetReservation: async () => ({ committed: true, idempotent: false }),
  revertSponsorBudgetReservation: async () => ({ reverted: true, idempotent: false })
};

await run("adds service JWT when proxying did create", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  let authHeader;
  const fetchImpl = async (_url, options) => {
    const headers = options?.headers;
    authHeader = headers?.Authorization ?? headers?.authorization;
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };
  const app = buildServer({
    configOverride: {
      ...config,
      GATEWAY_ALLOWED_VCTS: ["cuncta.marketplace.seller_good_standing"]
    },
    fetchImpl,
    ...sponsorBudgetPass
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/request",
    headers: { "x-device-id": "device-test-1" },
    payload: { network: "testnet", publicKeyMultibase: "z7ABC", options: {} }
  });
  assert.equal(response.statusCode, 200);
  assert.ok(typeof authHeader === "string" && authHeader.startsWith("Bearer "));
  await app.close();
});

await run("enforces device quota for DID submit", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: {
      ...config,
      RATE_LIMIT_DEVICE_DID_PER_DAY: 2,
      RATE_LIMIT_IP_DID_SUBMIT_PER_MIN: 100,
      GATEWAY_ALLOWED_VCTS: ["cuncta.marketplace.seller_good_standing"]
    },
    fetchImpl,
    ...sponsorBudgetPass
  });
  const payload = { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" };
  const headers = { "x-device-id": "device-test-2" };
  const first = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers,
    payload
  });
  const second = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers,
    payload
  });
  const third = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers,
    payload
  });
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(third.statusCode, 429);
  await app.close();
});

await run("enforces IP rate limit for DID submit", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: {
      ...config,
      RATE_LIMIT_IP_DID_SUBMIT_PER_MIN: 2,
      RATE_LIMIT_DEVICE_DID_PER_DAY: 50,
      GATEWAY_ALLOWED_VCTS: ["cuncta.marketplace.seller_good_standing"]
    },
    fetchImpl,
    ...sponsorBudgetPass
  });
  const payload = { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" };
  const headers = { "x-device-id": "device-test-3" };
  const first = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers,
    payload,
    remoteAddress: "203.0.113.10"
  });
  const second = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers,
    payload,
    remoteAddress: "203.0.113.10"
  });
  const third = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers,
    payload,
    remoteAddress: "203.0.113.10"
  });
  assert.equal(first.statusCode, 200);
  assert.equal(second.statusCode, 200);
  assert.equal(third.statusCode, 429);
  await app.close();
});

await run("sponsor budget denies when exceeded", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, RATE_LIMIT_DEVICE_DID_PER_DAY: 10 },
    fetchImpl,
    reserveSponsorBudget: async () => ({ allowed: false, reason: "budget_exceeded" }),
    commitSponsorBudgetReservation: async () => ({ committed: true, idempotent: false }),
    revertSponsorBudgetReservation: async () => ({ reverted: true, idempotent: false })
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers: { "x-device-id": "device-test-4" },
    payload: { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" }
  });
  assert.equal(response.statusCode, 429);
  await app.close();
});

await run("sponsor kill switch denies", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  const fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, RATE_LIMIT_DEVICE_DID_PER_DAY: 10 },
    fetchImpl,
    reserveSponsorBudget: async () => ({ allowed: false, reason: "kill_switch" }),
    commitSponsorBudgetReservation: async () => ({ committed: true, idempotent: false }),
    revertSponsorBudgetReservation: async () => ({ reverted: true, idempotent: false })
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers: { "x-device-id": "device-test-5" },
    payload: { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" }
  });
  assert.equal(response.statusCode, 503);
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
    fetchImpl,
    ...sponsorBudgetPass
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
    fetchImpl,
    ...sponsorBudgetPass
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
      configOverride: { ...config, NODE_ENV: "production", GATEWAY_VERIFY_DEBUG_REASONS: true }
    });
  }, /gateway_verify_debug_reasons_disabled/);
});

await run("commits sponsor reservation only on successful DID submit", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  let commitCount = 0;
  let revertCount = 0;
  const fetchImpl = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, RATE_LIMIT_DEVICE_DID_PER_DAY: 10 },
    fetchImpl,
    reserveSponsorBudget: async () => ({
      allowed: true,
      reservation: { id: "res-success", day: "2026-01-01", kind: "did_create", status: "RESERVED" }
    }),
    commitSponsorBudgetReservation: async () => {
      commitCount += 1;
      return { committed: true, idempotent: false };
    },
    revertSponsorBudgetReservation: async () => {
      revertCount += 1;
      return { reverted: true, idempotent: false };
    }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers: { "x-device-id": "device-test-budget-success" },
    payload: { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" }
  });
  assert.equal(response.statusCode, 200);
  assert.equal(commitCount, 1);
  assert.equal(revertCount, 0);
  await app.close();
});

await run("reverts sponsor reservation when DID submit downstream fails", async () => {
  setupEnv();
  const { buildServer } = await import("../server.ts");
  const { config } = await import("../config.ts");
  let commitCount = 0;
  let revertCount = 0;
  const fetchImpl = async () =>
    new Response(JSON.stringify({ error: "downstream_failed" }), {
      status: 503,
      headers: { "content-type": "application/json" }
    });
  const app = buildServer({
    configOverride: { ...config, RATE_LIMIT_DEVICE_DID_PER_DAY: 10 },
    fetchImpl,
    reserveSponsorBudget: async () => ({
      allowed: true,
      reservation: { id: "res-failed", day: "2026-01-01", kind: "did_create", status: "RESERVED" }
    }),
    commitSponsorBudgetReservation: async () => {
      commitCount += 1;
      return { committed: true, idempotent: false };
    },
    revertSponsorBudgetReservation: async () => {
      revertCount += 1;
      return { reverted: true, idempotent: false };
    }
  });
  const response = await app.inject({
    method: "POST",
    url: "/v1/onboard/did/create/submit",
    headers: { "x-device-id": "device-test-budget-fail" },
    payload: { state: "11111111-1111-1111-1111-111111111111", signatureB64u: "abc" }
  });
  assert.equal(response.statusCode, 503);
  assert.equal(commitCount, 0);
  assert.equal(revertCount, 1);
  await app.close();
});
