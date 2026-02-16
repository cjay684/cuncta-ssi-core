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
  await ensureMarketplaceListPolicy();
  const { getDb } = await import("../db.js");
  const db = await getDb();
  await db("policies").where({ policy_id: "dev.aura.signal.v1" }).del();
  await db("actions").where({ action_id: "dev.aura.signal" }).del();
  const logic = {
    binding: { mode: "kb-jwt", require: true },
    requirements: [
      {
        vct: "cuncta.marketplace.seller_good_standing",
        issuer: { mode: "env", env: "ISSUER_DID" },
        disclosures: ["seller_good_standing", "tier"],
        predicates: [
          { path: "seller_good_standing", op: "eq", value: true },
          { path: "domain", op: "eq", value: "marketplace" }
        ],
        revocation: { required: true }
      }
    ]
  };
  await db("policies")
    .where({ action_id: "marketplace.list_item" })
    .andWhere("version", ">", 1)
    .del();
  await db("policies")
    .where({ action_id: "marketplace.list_item" })
    .andWhereNot({ policy_id: "marketplace.list_item.v1" })
    .del();
  await db("policies").where({ policy_id: "marketplace.list_item.v1" }).update({
    logic
  });
  await db("policies").update({
    policy_hash: null,
    policy_signature: null
  });
  resetPolicyIntegrityCache();
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;
  const policy = await getPolicyForAction("marketplace.list_item");
  assert.ok(policy);
  assert.equal(policy?.actionId, "marketplace.list_item");
  assert.ok(policy?.logic.requirements.length);

  const noPolicy = await getPolicyForAction("unknown.action");
  assert.equal(noPolicy, null);
  const devPolicy = await getPolicyForAction("dev.aura.signal");
  assert.equal(devPolicy, null);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
