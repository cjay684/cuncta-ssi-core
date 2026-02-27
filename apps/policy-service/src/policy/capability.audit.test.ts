import { strict as assert } from "node:assert";

const run = async () => {
  process.env.NODE_ENV = "test";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.DATABASE_URL =
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
  process.env.DEV_MODE = "true";
  process.env.POLICY_SIGNING_JWK = JSON.stringify({
    crv: "Ed25519",
    kty: "OKP",
    x: "eizSDrSrl36htHi8iHaUO9Txf0nfp-JnQzSSdkuv4A0",
    d: "n6577z46eZat0Wv-el3Vg_LaJpVXo5ZYLZ_q5OMYpPk",
    kid: "policy-test"
  });
  process.env.POLICY_SIGNING_BOOTSTRAP = "true";
  process.env.ANCHOR_AUTH_SECRET =
    process.env.ANCHOR_AUTH_SECRET ?? "test-anchor-auth-secret-please-rotate";

  const { config } = await import("../config.js");
  config.DEV_MODE = true;
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;

  const { resetPolicyIntegrityCache } = await import("./integrity.js");
  const { getPolicyForAction } = await import("./evaluate.js");
  const { ensureMarketplaceListPolicy } = await import("../testUtils/seedPolicy.js");
  const { getDb } = await import("../db.js");

  // Ensure a baseline capability-gated action always exists in test DBs.
  await ensureMarketplaceListPolicy();

  const db = await getDb();
  const auraRules = (await db("aura_rules")
    .where({ enabled: true })
    .select("output_vct")) as Array<{
    output_vct?: unknown;
  }>;
  const auraVcts = new Set(
    auraRules.map((r) => String(r.output_vct ?? "").trim()).filter((vct) => vct.length > 0)
  );
  assert.ok(auraVcts.size > 0, "expected enabled aura_rules to exist");

  // Guardrail list: privileged writes that must require (at least one) Aura capability VC.
  // Keep this small and customer-facing; expand deliberately when new privileged actions are added.
  const privilegedActions = [
    "marketplace.list_item",
    "marketplace.list_high_value",
    "social.reply.create",
    "social.space.join",
    "social.space.post.create",
    "social.space.moderate"
  ];

  // If migrations or tests mutated policy integrity fields, normalize before reading.
  await db("policies").update({ policy_hash: null, policy_signature: null });
  resetPolicyIntegrityCache();

  for (const actionId of privilegedActions) {
    const policy = await getPolicyForAction(actionId);
    assert.ok(policy, `missing_policy:${actionId}`);
    const requirementVcts = (policy?.logic.requirements ?? []).map((r) => {
      const requirement = r as { vct?: unknown };
      return String(requirement.vct ?? "");
    });
    assert.ok(requirementVcts.length > 0, `missing_requirements:${actionId}`);
    const hasAuraCapability = requirementVcts.some((vct) => auraVcts.has(vct));
    assert.ok(
      hasAuraCapability,
      `capability_requirement_missing:${actionId} requirements=${JSON.stringify(requirementVcts)}`
    );
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
