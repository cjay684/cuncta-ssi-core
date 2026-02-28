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
  const { getDb } = await import("../db.js");

  const db = await getDb();

  const ssiActions = ["identity.verify"];

  await db("policies").update({ policy_hash: null, policy_signature: null });
  resetPolicyIntegrityCache();

  for (const actionId of ssiActions) {
    const policy = await getPolicyForAction(actionId);
    assert.ok(policy, `missing_policy:${actionId}`);
    const requirements = policy?.logic.requirements ?? [];
    assert.ok(requirements.length > 0, `missing_requirements:${actionId}`);
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
