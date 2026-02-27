import { test } from "node:test";
import assert from "node:assert/strict";

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

test("enabled aura_rule without purpose fails closed", async () => {
  const { getDb } = await import("../db.js");
  const { processAuraSignalsOnce } = await import("./auraWorker.js");

  const db = await getDb();
  const now = new Date().toISOString();

  await db("aura_rules").update({ enabled: false });
  await db("aura_rules").where({ rule_id: "test.missing.purpose.v1" }).del();

  await db("aura_rules").insert({
    rule_id: "test.missing.purpose.v1",
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    rule_logic: JSON.stringify({
      window_seconds: 3600,
      signals: ["marketplace.listing_success"],
      score: { min_silver: 1, min_gold: 2 },
      output: { claims: { seller_good_standing: true, domain: "{domain}", as_of: "{now}" } }
    }),
    enabled: true,
    version: 1,
    created_at: now,
    updated_at: now,
    rule_signature: null
  });

  await assert.rejects(async () => processAuraSignalsOnce(), /aura_integrity_failed/);
});
