import { test } from "node:test";
import assert from "node:assert/strict";
import { hashCanonicalJson } from "@cuncta/shared";

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

test("AURA_BATCH batch_hash is deterministic across event ordering", async () => {
  const { getDb } = await import("../db.js");
  const { getDidHashes } = await import("../pseudonymizer.js");
  const { ensureAuraRuleIntegrity } = await import("./auraIntegrity.js");
  const { processAuraSignalsOnce } = await import("./auraWorker.js");

  const db = await getDb();
  const now = new Date().toISOString();

  await db("anchor_outbox").where({ event_type: "AURA_BATCH" }).del();
  await db("aura_signals").where({ domain: "marketplace" }).del();
  await db("aura_rules").where({ rule_id: "test.batch.determinism.v1" }).del();

  await db("aura_rules").insert({
    rule_id: "test.batch.determinism.v1",
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    rule_logic: JSON.stringify({
      purpose: "Batch anchor determinism test",
      window_seconds: 3600,
      signals: ["marketplace.listing_success"],
      per_counterparty_cap: 3,
      collusion_cluster_threshold: 0.8,
      score: { min_silver: 1, min_gold: 2 },
      diversity_min: 1,
      min_tier: "bronze",
      output: { claims: { ok: true } }
    }),
    enabled: true,
    version: 7,
    created_at: now,
    updated_at: now,
    rule_signature: null
  });
  const inserted = (await db("aura_rules").where({ rule_id: "test.batch.determinism.v1" }).first()) as Record<
    string,
    unknown
  >;
  await ensureAuraRuleIntegrity(inserted as never);

  const subjectHash = getDidHashes("did:hedera:testnet:subject:batch:1").primary;
  await db("aura_signals").insert([
    {
      subject_did_hash: subjectHash,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      event_hash: "bbb",
      created_at: new Date(Date.now() - 2000).toISOString(),
      processed_at: null
    },
    {
      subject_did_hash: subjectHash,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      event_hash: "aaa",
      created_at: new Date(Date.now() - 1000).toISOString(),
      processed_at: null
    }
  ]);

  await processAuraSignalsOnce();

  const batch = (await db("anchor_outbox")
    .where({ event_type: "AURA_BATCH" })
    .orderBy("created_at", "desc")
    .first()) as { payload_meta?: unknown } | undefined;
  assert.ok(batch?.payload_meta, "expected AURA_BATCH anchor payload_meta");
  const meta = batch.payload_meta as Record<string, unknown>;
  assert.equal(meta.domain, "marketplace");
  assert.equal(meta.signal_count, 2);
  assert.equal(typeof meta.batch_hash, "string");

  const expectedBatchHash = hashCanonicalJson({
    event_hashes: ["aaa", "bbb"],
    rules: [
      {
        rule_id: "test.batch.determinism.v1",
        output_vct: "cuncta.marketplace.seller_good_standing",
        version: 7
      }
    ]
  });
  assert.equal(meta.batch_hash, expectedBatchHash);
});

