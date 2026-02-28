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
process.env.ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? "http://localhost:3002";

const run = async () => {
  const { getDb } = await import("../db.js");
  const { processAuraSignalsOnce } = await import("./auraWorker.js");
  const { getDidHashes } = await import("../pseudonymizer.js");

  const db = await getDb();
  await db("aura_signals").del();
  await db("aura_state").del();
  await db("aura_issuance_queue").del();
  await db("aura_rules").update({ enabled: false });
  await db("aura_rules").where("rule_id", "like", "test.auraWorker.%").del();

  const insertRule = async (
    ruleId: string,
    domain: string,
    signal: string,
    minSilver: number,
    minGold: number
  ) => {
    const now = new Date().toISOString();
    const vctSuffix = ruleId.replaceAll(".", "_");
    await db("aura_rules").insert({
      rule_id: ruleId,
      domain,
      output_vct: `cuncta.${domain}.${vctSuffix}`,
      rule_logic: JSON.stringify({
        purpose: `Capability for test rule ${ruleId} within domain ${domain}`,
        window_seconds: 3600,
        signals: [signal],
        score: { min_silver: minSilver, min_gold: minGold },
        per_counterparty_cap: 3,
        per_counterparty_decay_exponent: 0.5,
        diversity_min: 1,
        collusion_cluster_threshold: 0.6,
        collusion_multiplier: 0.7,
        min_tier: "bronze",
        output: {
          claims: {
            domain: "{domain}",
            tier: "{tier}",
            as_of: "{now}"
          }
        }
      }),
      enabled: true,
      version: 1,
      created_at: now,
      updated_at: now
    });
  };

  const insertSignals = async (
    subjectHash: string,
    domain: string,
    signal: string,
    counterpartyHashes: string[],
    prefix: string
  ) => {
    const now = new Date().toISOString();
    await db("aura_signals").insert(
      counterpartyHashes.map((counterpartyHash, index) => ({
        subject_did_hash: subjectHash,
        domain,
        signal,
        weight: 2,
        counterparty_did_hash: counterpartyHash,
        event_hash: sha256Hex(`${prefix}-${index}`),
        created_at: now
      }))
    );
  };

  const subjectDid = "did:example:holder:aura";
  const subjectHash = getDidHashes(subjectDid).primary;
  const counterpartyHash = getDidHashes("did:example:counterparty:1").primary;
  const counterpartyHash2 = getDidHashes("did:example:counterparty:2").primary;

  await insertRule(
    "test.auraWorker.marketplace.v1",
    "marketplace",
    "marketplace.listing_success",
    1,
    2
  );
  await insertSignals(
    subjectHash,
    "marketplace",
    "marketplace.listing_success",
    [counterpartyHash, counterpartyHash2],
    "marketplace-signal"
  );

  await processAuraSignalsOnce();

  const state = await db("aura_state")
    .where({ subject_did_hash: subjectHash, domain: "marketplace" })
    .first();
  assert.ok(state, "aura_state should be updated");

  const queue = await db("aura_issuance_queue").where({ subject_did_hash: subjectHash }).first();
  assert.ok(queue, "aura issuance queue should be populated");

  // A) Same-pass aggregation for social domain keeps highest tier.
  await db("aura_signals").del();
  await db("aura_state").where({ subject_did_hash: subjectHash, domain: "social" }).del();
  await db("aura_rules")
    .whereIn("rule_id", ["test.auraWorker.social.high.v1", "test.auraWorker.social.low.v1"])
    .del();
  await insertRule("test.auraWorker.social.high.v1", "social", "social.post_success", 1, 100);
  await insertRule("test.auraWorker.social.low.v1", "social", "social.post_success", 10, 100);
  await insertSignals(
    subjectHash,
    "social",
    "social.post_success",
    [counterpartyHash, counterpartyHash2],
    "social-pass-a"
  );
  await processAuraSignalsOnce();
  const socialStateA = await db("aura_state")
    .where({ subject_did_hash: subjectHash, domain: "social" })
    .first();
  assert.equal(socialStateA?.state?.tier, "silver", "same pass should persist highest social tier");

  // B) Rule order independence for same-pass social aggregation.
  await db("aura_signals").del();
  await db("aura_state").where({ subject_did_hash: subjectHash, domain: "social" }).del();
  await db("aura_rules")
    .whereIn("rule_id", ["test.auraWorker.social.high.v1", "test.auraWorker.social.low.v1"])
    .del();
  await insertRule("test.auraWorker.social.low.v1", "social", "social.post_success", 10, 100);
  await insertRule("test.auraWorker.social.high.v1", "social", "social.post_success", 1, 100);
  await insertSignals(
    subjectHash,
    "social",
    "social.post_success",
    [counterpartyHash, counterpartyHash2],
    "social-pass-b"
  );
  await processAuraSignalsOnce();
  const socialStateB = await db("aura_state")
    .where({ subject_did_hash: subjectHash, domain: "social" })
    .first();
  assert.equal(
    socialStateB?.state?.tier,
    "silver",
    "social tier should be order-independent in one pass"
  );

  // C) Across passes, social tier can downgrade (not monotonic best-ever).
  await db("aura_signals").del();
  await db("aura_rules")
    .whereIn("rule_id", ["test.auraWorker.social.high.v1", "test.auraWorker.social.low.v1"])
    .update({
      rule_logic: JSON.stringify({
        window_seconds: 3600,
        signals: ["social.post_success"],
        score: { min_silver: 999, min_gold: 1000 },
        per_counterparty_cap: 3,
        per_counterparty_decay_exponent: 0.5,
        diversity_min: 1,
        collusion_cluster_threshold: 0.6,
        collusion_multiplier: 0.7,
        min_tier: "bronze",
        output: { claims: { domain: "{domain}", tier: "{tier}", as_of: "{now}" } }
      }),
      updated_at: new Date().toISOString()
    });
  await insertSignals(
    subjectHash,
    "social",
    "social.post_success",
    [counterpartyHash],
    "social-pass-c"
  );
  await processAuraSignalsOnce();
  const socialStateC = await db("aura_state")
    .where({ subject_did_hash: subjectHash, domain: "social" })
    .first();
  assert.equal(
    socialStateC?.state?.tier,
    "bronze",
    "next pass should be able to downgrade social tier"
  );
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
