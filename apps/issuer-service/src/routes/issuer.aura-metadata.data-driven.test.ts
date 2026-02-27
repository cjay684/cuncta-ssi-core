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

test("OID4VCI Aura metadata is derived from enabled aura_rules (no hardcoding)", async () => {
  const { getDb } = await import("../db.js");
  const { ensureAuraRuleIntegrity } = await import("../aura/auraIntegrity.js");
  const { buildOid4vciIssuerMetadata } = await import("./issuer.js");

  const db = await getDb();
  const now = new Date().toISOString();
  const outputVct = "cuncta.test.dynamic_capability_v1";
  const ruleId = "test.dynamic.capability.v1";

  await db("aura_rules").where({ rule_id: ruleId }).del();

  await db("aura_rules").insert({
    rule_id: ruleId,
    domain: "social",
    output_vct: outputVct,
    rule_logic: JSON.stringify({
      purpose: "Dynamic capability test purpose",
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
  const inserted = (await db("aura_rules").where({ rule_id: ruleId }).first()) as Record<
    string,
    unknown
  >;
  await ensureAuraRuleIntegrity(inserted as never);

  const metadata = await buildOid4vciIssuerMetadata({
    issuerBaseUrl: "http://localhost:3002",
    allowExperimentalZk: false
  });
  const supported = (metadata as { credential_configurations_supported?: Record<string, unknown> })
    .credential_configurations_supported;
  assert.ok(supported);

  const configId = `aura:${outputVct}`;
  assert.ok(
    configId in supported,
    "new enabled aura_rule should appear as aura:<output_vct> config"
  );
  const cfg = supported[configId] as Record<string, unknown>;
  assert.equal(cfg.vct, outputVct);
  const capability = (cfg.capability ?? {}) as Record<string, unknown>;
  assert.equal(capability.domain_pattern, "social");
  assert.equal(capability.purpose, "Dynamic capability test purpose");
});
