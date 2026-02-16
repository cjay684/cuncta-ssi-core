import { strict as assert } from "node:assert";
import { sha256Hex } from "../crypto/sha256.js";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
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

const run = async () => {
  const { getDb } = await import("../db.js");
  const { processAuraSignalsOnce } = await import("./auraWorker.js");
  const { getDidHashes } = await import("../pseudonymizer.js");

  const db = await getDb();
  await db("aura_signals").del();
  await db("aura_state").del();
  await db("aura_issuance_queue").del();
  await db("aura_rules").update({ enabled: false });
  await db("aura_rules").where({ rule_id: "test.auraWorker.v1" }).del();
  await db("aura_rules").insert({
    rule_id: "test.auraWorker.v1",
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    rule_logic: JSON.stringify({
      window_seconds: 3600,
      signals: ["marketplace.listing_success"],
      score: { min_silver: 1, min_gold: 2 },
      per_counterparty_cap: 3,
      per_counterparty_decay_exponent: 0.5,
      diversity_min: 1,
      collusion_cluster_threshold: 0.6,
      collusion_multiplier: 0.7,
      min_tier: "bronze",
      output: {
        claims: {
          seller_good_standing: true,
          domain: "{domain}",
          tier: "{tier}",
          as_of: "{now}"
        }
      }
    }),
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const subjectDid = "did:example:holder:aura";
  const subjectHash = getDidHashes(subjectDid).primary;
  const counterpartyHash = getDidHashes("did:example:counterparty:1").primary;

  await db("aura_signals").insert([
    {
      subject_did_hash: subjectHash,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 2,
      counterparty_did_hash: counterpartyHash,
      event_hash: sha256Hex("signal-1"),
      created_at: new Date().toISOString()
    },
    {
      subject_did_hash: subjectHash,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 2,
      counterparty_did_hash: getDidHashes("did:example:counterparty:2").primary,
      event_hash: sha256Hex("signal-2"),
      created_at: new Date().toISOString()
    }
  ]);

  await processAuraSignalsOnce();

  const state = await db("aura_state")
    .where({ subject_did_hash: subjectHash, domain: "marketplace" })
    .first();
  assert.ok(state, "aura_state should be updated");

  const queue = await db("aura_issuance_queue").where({ subject_did_hash: subjectHash }).first();
  assert.ok(queue, "aura issuance queue should be populated");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
