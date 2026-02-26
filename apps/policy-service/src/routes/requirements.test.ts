import { strict as assert } from "node:assert";

process.env.NODE_ENV = "test";
process.env.HEDERA_NETWORK = "testnet";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.POLICY_SIGNING_JWK = JSON.stringify({
  crv: "Ed25519",
  kty: "OKP",
  x: "eizSDrSrl36htHi8iHaUO9Txf0nfp-JnQzSSdkuv4A0",
  d: "n6577z46eZat0Wv-el3Vg_LaJpVXo5ZYLZ_q5OMYpPk",
  kid: "policy-test"
});
process.env.POLICY_SIGNING_BOOTSTRAP = "true";
process.env.ANCHOR_AUTH_SECRET = "test-anchor-auth-secret-please-rotate";

const run = async () => {
  const { config } = await import("../config.js");
  const { ensureMarketplaceListPolicy } = await import("../testUtils/seedPolicy.js");
  const { resetPolicyIntegrityCache } = await import("../policy/integrity.js");
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;
  resetPolicyIntegrityCache();
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");

  const app = buildServer();
  await app.ready();

  const db = await getDb();
  await ensureMarketplaceListPolicy();
  await db("verification_challenges").del();
  await db("policies").where({ policy_id: "marketplace.list_item.v2" }).del();
  await db("policies")
    .where({ action_id: "marketplace.list_item" })
    .andWhereNot({ policy_id: "marketplace.list_item.v1" })
    .del();
  await db("policies")
    .where({ policy_id: "marketplace.list_item.v1" })
    .update({
      logic: {
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
      }
    });
  await db("policies").update({
    policy_hash: null,
    policy_signature: null
  });
  resetPolicyIntegrityCache();

  const v1 = await db("policies").where({ policy_id: "marketplace.list_item.v1" }).first();
  assert.ok(v1, "expected marketplace.list_item.v1 policy");

  const v1Response = await app.inject({
    method: "GET",
    url: "/v1/requirements?action=marketplace.list_item"
  });
  assert.equal(v1Response.statusCode, 200);
  const v1Payload = v1Response.json() as { policyId?: string; version?: number };
  assert.equal(v1Payload.policyId, "marketplace.list_item.v1");
  assert.equal(v1Payload.version, 1);
  const v1Challenge = await db("verification_challenges")
    .where({
      action_id: "marketplace.list_item",
      policy_id: "marketplace.list_item.v1",
      policy_version: 1
    })
    .orderBy("created_at", "desc")
    .first();
  assert.ok(v1Challenge, "challenge should pin policy v1");

  const v1LogicRaw = v1.logic as unknown;
  const v1Logic =
    typeof v1LogicRaw === "string"
      ? (JSON.parse(v1LogicRaw) as Record<string, unknown>)
      : (v1LogicRaw as Record<string, unknown>);
  await db("policies").insert({
    policy_id: "marketplace.list_item.v2",
    action_id: "marketplace.list_item",
    version: 2,
    enabled: true,
    logic: JSON.stringify(v1Logic),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const v2Response = await app.inject({
    method: "GET",
    url: "/v1/requirements?action=marketplace.list_item"
  });
  assert.equal(v2Response.statusCode, 200);
  const v2Payload = v2Response.json() as { policyId?: string; version?: number };
  assert.equal(v2Payload.policyId, "marketplace.list_item.v2");
  assert.equal(v2Payload.version, 2);
  const v2Challenge = await db("verification_challenges")
    .where({
      action_id: "marketplace.list_item",
      policy_id: "marketplace.list_item.v2",
      policy_version: 2
    })
    .orderBy("created_at", "desc")
    .first();
  assert.ok(v2Challenge, "challenge should pin policy v2");

  await app.close();
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
