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
  await db("aura_rules").where({ rule_id: "test.rule.v1" }).del();

  await db("aura_rules").insert({
    rule_id: "test.rule.v1",
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    rule_logic: JSON.stringify({
      window_seconds: 3600,
      per_counterparty_cap: 5,
      per_counterparty_decay_exponent: 0.5,
      diversity_min: 3,
      collusion_cluster_threshold: 0.6,
      collusion_multiplier: 0.5,
      score: { min_silver: 3, min_gold: 6 },
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

  const subjectA = getDidHashes("did:example:a").primary;
  const subjectB = getDidHashes("did:example:b").primary;
  const subjectC = getDidHashes("did:example:c").primary;

  const now = new Date().toISOString();
  const sameCounterparty = getDidHashes("did:example:counterparty:same").primary;

  for (let i = 0; i < 5; i += 1) {
    await db("aura_signals").insert({
      subject_did_hash: subjectA,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      counterparty_did_hash: sameCounterparty,
      event_hash: sha256Hex(`a-${i}`),
      created_at: now
    });
  }

  for (let i = 0; i < 5; i += 1) {
    await db("aura_signals").insert({
      subject_did_hash: subjectB,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      counterparty_did_hash: getDidHashes(`did:example:counterparty:${i}`).primary,
      event_hash: sha256Hex(`b-${i}`),
      created_at: now
    });
  }

  for (let i = 0; i < 10; i += 1) {
    await db("aura_signals").insert({
      subject_did_hash: subjectC,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      counterparty_did_hash: getDidHashes(`did:example:counterparty:${i % 2}`).primary,
      event_hash: sha256Hex(`c-${i}`),
      created_at: now
    });
  }

  await processAuraSignalsOnce();

  const stateA = await db("aura_state")
    .where({ subject_did_hash: subjectA, domain: "marketplace" })
    .first();
  const stateB = await db("aura_state")
    .where({ subject_did_hash: subjectB, domain: "marketplace" })
    .first();
  const stateC = await db("aura_state")
    .where({ subject_did_hash: subjectC, domain: "marketplace" })
    .first();

  const scoreA = Number((stateA?.state as { score?: number } | undefined)?.score ?? 0);
  const scoreB = Number((stateB?.state as { score?: number } | undefined)?.score ?? 0);
  const scoreC = Number((stateC?.state as { score?: number } | undefined)?.score ?? 0);

  assert.ok(scoreB > scoreA, "diversity should increase effective score");
  assert.ok(scoreC < scoreB, "collusion down-weighting should reduce score");

  const queueA = await db("aura_issuance_queue").where({ subject_did_hash: subjectA }).first();
  const queueB = await db("aura_issuance_queue").where({ subject_did_hash: subjectB }).first();
  assert.equal(queueA, undefined);
  assert.ok(queueB);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
