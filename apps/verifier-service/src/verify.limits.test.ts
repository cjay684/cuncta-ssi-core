import { strict as assert } from "node:assert";
import { randomUUID } from "node:crypto";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { hashCanonicalJson } from "@cuncta/shared";
import { sha256Hex } from "./crypto/sha256.js";

process.env.NODE_ENV = "test";
process.env.ISSUER_SERVICE_BASE_URL = "http://localhost:3002";
process.env.POLICY_SERVICE_BASE_URL = "http://localhost:3004";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.VERIFY_MAX_PRESENTATION_BYTES = "4096";

const run = async () => {
  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.kid = "policy-test";
  privateJwk.alg = "EdDSA";
  privateJwk.crv = "Ed25519";
  privateJwk.kty = "OKP";
  process.env.POLICY_SIGNING_JWK = JSON.stringify(privateJwk);

  const { config } = await import("./config.js");
  config.VERIFY_MAX_PRESENTATION_BYTES = 4096;
  config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://localhost:3002";
  config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://localhost:3004";
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;

  const { buildServer } = await import("./server.js");
  const { getDb } = await import("./db.js");
  const { closeDb } = await import("@cuncta/db");

  const db = await getDb();
  const policyId = `test.policy.${randomUUID()}`;
  const actionId = `test.action.${randomUUID()}`;
  const version = 1;
  const logic = { binding: { mode: "kb-jwt", require: true }, requirements: [], obligations: [] };
  const policyHash = hashCanonicalJson({
    policy_id: policyId,
    action_id: actionId,
    version,
    enabled: true,
    logic
  });
  const policySignature = await new SignJWT({ hash: policyHash })
    .setProtectedHeader({ alg: "EdDSA", typ: "policy-hash+jwt", kid: privateJwk.kid })
    .setIssuedAt()
    .sign(privateKey);

  const now = new Date().toISOString();
  await db("actions").insert({
    action_id: actionId,
    description: "Test action",
    created_at: now,
    updated_at: now
  });

  await db("policies").insert({
    policy_id: policyId,
    action_id: actionId,
    version,
    enabled: true,
    logic: JSON.stringify(logic),
    policy_hash: policyHash,
    policy_signature: policySignature,
    created_at: now,
    updated_at: now
  });

  const nonce = `nonce-${randomUUID()}`;
  const audience = `origin:https://verifier.cuncta.test/${actionId}`;
  const challengeHash = sha256Hex(nonce);
  const challengeId = randomUUID();
  await db("verification_challenges").insert({
    challenge_id: challengeId,
    challenge_hash: challengeHash,
    action_id: actionId,
    audience,
    policy_id: policyId,
    policy_version: version,
    policy_hash: policyHash,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
    created_at: now
  });

  const app = buildServer();
  await app.ready();

  const largePresentation = "a".repeat(5000);
  const largeResponse = await app.inject({
    method: "POST",
    url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
    payload: { presentation: largePresentation, nonce, audience }
  });
  console.error(
    "TEST_DIAG:verify_limits_large_response",
    JSON.stringify({ statusCode: largeResponse.statusCode, body: largeResponse.body, audience })
  );
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: "verify-limits-pre-fix",
      hypothesisId: "H1",
      location: "apps/verifier-service/src/verify.limits.test.ts:largeResponse",
      message: "large presentation response details",
      data: {
        audience,
        statusCode: largeResponse.statusCode,
        body: largeResponse.body
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  assert.equal(largeResponse.statusCode, 413);

  const bindingResponse = await app.inject({
    method: "POST",
    url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
    payload: { presentation: "presentation-token~", nonce, audience }
  });
  console.error(
    "TEST_DIAG:verify_limits_binding_response",
    JSON.stringify({ statusCode: bindingResponse.statusCode, body: bindingResponse.body, audience })
  );
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: "verify-limits-pre-fix",
      hypothesisId: "H2",
      location: "apps/verifier-service/src/verify.limits.test.ts:bindingResponse",
      message: "binding path response details",
      data: {
        audience,
        statusCode: bindingResponse.statusCode,
        body: bindingResponse.body
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  assert.equal(bindingResponse.statusCode, 200);
  const bindingPayload = bindingResponse.json() as { decision?: string; reasons?: string[] };
  assert.equal(bindingPayload.decision, "DENY");
  assert.ok(bindingPayload.reasons?.includes("kb_jwt_missing"));

  await app.close();
  await db("verification_challenges").where({ challenge_id: challengeId }).del();
  await db("policies").where({ policy_id: policyId }).del();
  await db("actions").where({ action_id: actionId }).del();
  await closeDb(db);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
