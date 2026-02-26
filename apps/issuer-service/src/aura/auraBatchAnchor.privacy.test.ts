import { test } from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "issuer-test-pepper-123456";
process.env.POLICY_SIGNING_JWK =
  process.env.POLICY_SIGNING_JWK ??
  JSON.stringify({
    crv: "Ed25519",
    kty: "OKP",
    x: "eizSDrSrl36htHi8iHaUO9Txf0nfp-JnQzSSdkuv4A0",
    d: "n6577z46eZat0Wv-el3Vg_LaJpVXo5ZYLZ_q5OMYpPk",
    kid: "policy-test"
  });
process.env.POLICY_SIGNING_BOOTSTRAP = "true";
process.env.ANCHOR_AUTH_SECRET =
  process.env.ANCHOR_AUTH_SECRET ?? "test-anchor-auth-secret-please-rotate";

test("AURA_BATCH anchor payload is privacy-safe (no subject hashes)", async () => {
  const { getDb } = await import("../db.js");
  const { getDidHashes } = await import("../pseudonymizer.js");
  const { ensureAuraRuleIntegrity } = await import("./auraIntegrity.js");
  const { processAuraSignalsOnce } = await import("./auraWorker.js");

  const db = await getDb();
  const now = new Date().toISOString();

  await db("anchor_outbox").where({ event_type: "AURA_BATCH" }).del();
  await db("aura_signals").where({ domain: "social" }).del();
  await db("aura_rules").where({ rule_id: "test.batch.privacy.v1" }).del();

  await db("aura_rules").insert({
    rule_id: "test.batch.privacy.v1",
    domain: "social",
    output_vct: "cuncta.social.can_post",
    rule_logic: JSON.stringify({
      purpose: "Batch anchor privacy test",
      window_seconds: 3600,
      signals: ["social.post.create"],
      score: { min_silver: 1, min_gold: 2 },
      diversity_min: 0,
      min_tier: "bronze",
      output: { claims: { ok: true } }
    }),
    enabled: true,
    version: 1,
    created_at: now,
    updated_at: now,
    rule_signature: null
  });
  const inserted = (await db("aura_rules").where({ rule_id: "test.batch.privacy.v1" }).first()) as Record<
    string,
    unknown
  >;
  await ensureAuraRuleIntegrity(inserted as never);

  const subjectHash = getDidHashes("did:hedera:testnet:subject:batch:privacy").primary;
  await db("aura_signals").insert({
    subject_did_hash: subjectHash,
    domain: "social",
    signal: "social.post.create",
    weight: 1,
    event_hash: "evt_priv_1",
    created_at: new Date().toISOString(),
    processed_at: null
  });

  await processAuraSignalsOnce();

  const batch = (await db("anchor_outbox")
    .where({ event_type: "AURA_BATCH" })
    .orderBy("created_at", "desc")
    .first()) as { payload_meta?: unknown } | undefined;
  assert.ok(batch?.payload_meta, "expected AURA_BATCH payload_meta");
  const meta = batch.payload_meta as Record<string, unknown>;

  // Required fields only (no subject linkage).
  assert.equal(meta.domain, "social");
  assert.equal(typeof meta.window_start, "string");
  assert.equal(typeof meta.window_end, "string");
  assert.equal(typeof meta.signal_count, "number");
  assert.equal(typeof meta.batch_hash, "string");

  const metaString = JSON.stringify(meta);
  assert.ok(!metaString.includes(subjectHash), "anchor payload must not contain subject hash values");
  assert.ok(!metaString.includes("subject_did_hash"), "anchor payload must not contain subject_did_hash keys");
  assert.ok(!metaString.includes("event_hashes"), "anchor payload must not expose per-event hashes");
});

