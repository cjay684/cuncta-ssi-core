import { strict as assert } from "node:assert";
import { hashCanonicalJson } from "@cuncta/shared";

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
process.env.POLICY_SIGNING_BOOTSTRAP = "false";

const run = async () => {
  const { config } = await import("../config.js");
  const { ensureMarketplaceListPolicy } = await import("../testUtils/seedPolicy.js");
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = false;

  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");

  const app = buildServer();
  await app.ready();

  const db = await getDb();
  await ensureMarketplaceListPolicy();
  await db("policies")
    .where({ action_id: "marketplace.list_item" })
    .andWhereNot({ policy_id: "marketplace.list_item.v1" })
    .del();
  const policyRow = await db("policies").where({ policy_id: "marketplace.list_item.v1" }).first();
  assert.ok(policyRow, "expected seed policy marketplace.list_item.v1");

  const logicRaw = policyRow.logic as unknown;
  const logic =
    typeof logicRaw === "string"
      ? (JSON.parse(logicRaw) as Record<string, unknown>)
      : (logicRaw as Record<string, unknown>);
  const policyHash = hashCanonicalJson({
    policy_id: policyRow.policy_id,
    action_id: policyRow.action_id,
    version: policyRow.version,
    enabled: policyRow.enabled,
    logic
  });

  const originalHash = policyRow.policy_hash ?? null;
  const originalSignature = policyRow.policy_signature ?? null;

  await db("policies").where({ policy_id: policyRow.policy_id }).update({
    policy_hash: policyHash,
    policy_signature: "invalid.signature",
    updated_at: new Date().toISOString()
  });

  const response = await app.inject({
    method: "GET",
    url: "/v1/requirements?action=marketplace.list_item"
  });
  assert.equal(response.statusCode, 503);
  const payload = response.json() as { error?: string };
  assert.equal(payload.error, "policy_integrity_failed");

  await db("policies").where({ policy_id: policyRow.policy_id }).update({
    policy_hash: originalHash,
    policy_signature: originalSignature,
    updated_at: new Date().toISOString()
  });

  await app.close();
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
