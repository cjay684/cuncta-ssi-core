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

test("at most one enabled aura_rule per (domain, output_vct)", async () => {
  const { getDb } = await import("../db.js");
  const db = await getDb();
  const now = new Date().toISOString();
  const domain = "social";
  const outputVct = "cuncta.test.duplicate_enabled_v1";

  await db("aura_rules")
    .whereIn("rule_id", ["test.dup.enabled.a.v1", "test.dup.enabled.b.v1"])
    .del();

  await db("aura_rules").insert({
    rule_id: "test.dup.enabled.a.v1",
    domain,
    output_vct: outputVct,
    rule_logic: JSON.stringify({
      purpose: "dup test",
      window_seconds: 60,
      output: { claims: { ok: true } }
    }),
    enabled: true,
    version: 1,
    created_at: now,
    updated_at: now,
    rule_signature: "test-signature-placeholder"
  });

  let threw = false;
  try {
    await db("aura_rules").insert({
      rule_id: "test.dup.enabled.b.v1",
      domain,
      output_vct: outputVct,
      rule_logic: JSON.stringify({
        purpose: "dup test",
        window_seconds: 60,
        output: { claims: { ok: true } }
      }),
      enabled: true,
      version: 2,
      created_at: now,
      updated_at: now,
      rule_signature: "test-signature-placeholder"
    });
  } catch {
    threw = true;
  }

  if (!threw) {
    // If the DB constraint is missing, enforce via a failing assertion to prevent production drift.
    const enabled = await db("aura_rules").where({ enabled: true, domain, output_vct: outputVct });
    assert.equal(enabled.length, 1);
  }
});
