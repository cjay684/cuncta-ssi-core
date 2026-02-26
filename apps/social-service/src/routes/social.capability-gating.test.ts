import { test } from "node:test";
import assert from "node:assert/strict";
import { createHmacSha256Pseudonymizer } from "@cuncta/shared";

process.env.NODE_ENV = "development";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "social-test-pepper-123456";
process.env.APP_GATEWAY_BASE_URL = process.env.APP_GATEWAY_BASE_URL ?? "http://localhost:3010";
process.env.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://localhost:3002";
process.env.ISSUER_PRIVACY_STATUS_TIMEOUT_MS = process.env.ISSUER_PRIVACY_STATUS_TIMEOUT_MS ?? "300";
process.env.SERVICE_JWT_SECRET =
  process.env.SERVICE_JWT_SECRET ?? "test-social-secret-012345678901234567890123";
process.env.SERVICE_JWT_SECRET_ISSUER =
  process.env.SERVICE_JWT_SECRET_ISSUER ?? "test-issuer-secret-012345678901234567890123";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

const makeJsonResponse = (payload: unknown, status = 200) =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" }
  });

test("writes are capability-VC gated (not aura_state tierRank authorized)", async () => {
  const originalFetch = globalThis.fetch;
  let verifyCalled = false;
  globalThis.fetch = (async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/v1/admin/privacy/status")) {
      return makeJsonResponse({ restricted: false, tombstoned: false });
    }
    if (url.includes("/v1/requirements")) {
      return makeJsonResponse({
        requirements: [{ vct: "cuncta.social.can_post", label: "Ability to post" }]
      });
    }
    if (url.includes("/v1/verify")) {
      verifyCalled = true;
      return makeJsonResponse({ decision: "DENY", reasons: ["missing_capability_vc"] });
    }
    return makeJsonResponse({}, 404);
  }) as typeof fetch;

  const { getDb } = await import("../db.js");
  const db = await getDb();
  const pseudonymizer = createHmacSha256Pseudonymizer({ pepper: process.env.PSEUDONYMIZER_PEPPER! });
  const subjectDid = "did:hedera:testnet:subject:capability-gating";
  const subjectHash = pseudonymizer.didToHash(subjectDid);
  const now = new Date().toISOString();
  // Even if aura_state says "gold", write must still be gated via verifier policy checks.
  await db("aura_state")
    .insert({
      subject_did_hash: subjectHash,
      domain: "social",
      state: { tier: "gold", score: 999, diversity: 99, window_days: 30, last_signal_at: now },
      updated_at: now
    })
    .onConflict(["subject_did_hash", "domain"])
    .merge({
      state: { tier: "gold", score: 999, diversity: 99, window_days: 30, last_signal_at: now },
      updated_at: now
    });

  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/v1/social/post",
    payload: {
      subjectDid,
      content: "hello world",
      visibility: "public",
      presentation: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkaWQifQ.signature",
      nonce: "nonce-social-post-12345",
      audience: "cuncta.action:social.post.create"
    }
  });
  assert.equal(response.statusCode, 403);
  assert.equal(verifyCalled, true, "write route must call verifier (verifyAndGate)");
  await app.close();
  globalThis.fetch = originalFetch;
});

