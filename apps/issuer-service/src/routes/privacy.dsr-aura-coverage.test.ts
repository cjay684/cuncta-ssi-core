import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

process.env.NODE_ENV = "test";
process.env.ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.DEV_MODE = "true";
process.env.ISSUER_DID = process.env.ISSUER_DID ?? "did:example:issuer";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "issuer-test-pepper-123456";

test("DSR erase removes aura_* and obligations_* rows for subject", async () => {
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { sha256Hex } = await import("../crypto/sha256.js");
  const { getDidHashes } = await import("../pseudonymizer.js");

  const app = buildServer();
  await app.ready();
  const db = await getDb();

  const did = "did:hedera:testnet:subject:dsr-aura";
  const didHash = getDidHashes(did).primary;
  const now = new Date().toISOString();

  const dsrToken = randomBytes(24).toString("base64url");
  const tokenHash = sha256Hex(dsrToken);
  const expiresAt = new Date(Date.now() + 60_000).toISOString();

  await db("privacy_tokens").where({ did_hash: didHash }).del();
  await db("privacy_tokens").insert({
    token_hash: tokenHash,
    did_hash: didHash,
    did_hash_legacy: null,
    expires_at: expiresAt,
    created_at: now
  });

  await db("aura_signals").where({ subject_did_hash: didHash }).del();
  await db("aura_state").where({ subject_did_hash: didHash }).del();
  await db("aura_issuance_queue").where({ subject_did_hash: didHash }).del();
  await db("obligations_executions").where({ subject_did_hash: didHash }).del();

  await db("aura_signals").insert({
    subject_did_hash: didHash,
    domain: "social",
    signal: "social.post.create",
    weight: 1,
    event_hash: "evt_dsr_1",
    created_at: now,
    processed_at: null
  });
  await db("aura_state").insert({
    subject_did_hash: didHash,
    domain: "social",
    state: { tier: "silver", score: 2, diversity: 1, window_days: 30, last_signal_at: now },
    updated_at: now
  });
  await db("aura_issuance_queue").insert({
    queue_id: "aq_dsr_test",
    rule_id: "rule_dsr_test",
    subject_did_hash: didHash,
    domain: "social",
    output_vct: "cuncta.social.can_post",
    reason_hash: "rh_dsr_test",
    status: "PENDING",
    created_at: now,
    updated_at: now
  });
  await db("obligations_executions").insert({
    id: "oe_dsr_test",
    action_id: "social.post.create",
    policy_id: "policy_dsr_test",
    policy_version: 1,
    decision: "ALLOW",
    subject_did_hash: didHash,
    token_hash: "token_hash_dsr_test",
    challenge_hash: "challenge_hash_dsr_test",
    obligations_hash: "obligations_hash_dsr_test",
    executed_at: now,
    anchor_payload_hash: "anchor_payload_hash_dsr_test",
    status: "PENDING",
    error_code: null
  });

  const response = await app.inject({
    method: "POST",
    url: "/v1/privacy/erase",
    headers: { Authorization: `Bearer ${dsrToken}` },
    payload: { mode: "unlink" }
  });
  assert.equal(response.statusCode, 200);
  const payload = response.json() as { status?: string };
  assert.equal(payload.status, "erased");

  const remainingSignals = await db("aura_signals").where({ subject_did_hash: didHash }).first();
  const remainingState = await db("aura_state").where({ subject_did_hash: didHash }).first();
  const remainingQueue = await db("aura_issuance_queue").where({ subject_did_hash: didHash }).first();
  const remainingObligations = await db("obligations_executions").where({ subject_did_hash: didHash }).first();

  assert.equal(Boolean(remainingSignals), false);
  assert.equal(Boolean(remainingState), false);
  assert.equal(Boolean(remainingQueue), false);
  assert.equal(Boolean(remainingObligations), false);

  await app.close();
});

