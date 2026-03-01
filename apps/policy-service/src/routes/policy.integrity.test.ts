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
  const { ensureIdentityVerifyPolicy } = await import("../testUtils/seedPolicy.js");
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = false;

  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");

  const app = buildServer();
  await app.ready();

  const db = await getDb();
  await ensureIdentityVerifyPolicy();
  const policyRows = await db("policies").where({ action_id: "identity.verify" });
  assert.ok(policyRows.length > 0, "expected at least one identity.verify policy");

  const originals = policyRows.map((row) => ({
    policy_id: row.policy_id as string,
    policy_hash: (row.policy_hash as string | null | undefined) ?? null,
    policy_signature: (row.policy_signature as string | null | undefined) ?? null
  }));

  try {
    // Tamper all candidate rows so whichever version evaluator picks fails integrity.
    for (const row of policyRows) {
      const logicRaw = row.logic as unknown;
      const logic =
        typeof logicRaw === "string"
          ? (JSON.parse(logicRaw) as Record<string, unknown>)
          : (logicRaw as Record<string, unknown>);
      const policyHash = hashCanonicalJson({
        policy_id: row.policy_id,
        action_id: row.action_id,
        version: row.version,
        enabled: row.enabled,
        logic
      });
      await db("policies").where({ policy_id: row.policy_id }).update({
        policy_hash: policyHash,
        policy_signature: "invalid.signature",
        updated_at: new Date().toISOString()
      });
    }

    const response = await app.inject({
      method: "GET",
      url: "/v1/requirements?action=identity.verify"
    });
    assert.equal(response.statusCode, 503);
    const payload = response.json() as { error?: string };
    assert.equal(payload.error, "policy_integrity_failed");
  } finally {
    for (const original of originals) {
      await db("policies").where({ policy_id: original.policy_id }).update({
        policy_hash: original.policy_hash,
        policy_signature: original.policy_signature,
        updated_at: new Date().toISOString()
      });
    }
    await app.close();
  }
};

run().catch((error) => {
  if (error instanceof Error) {
    console.error(error.message);
    if (error.stack) console.error(error.stack);
  } else {
    console.error(String(error));
  }
  process.exit(1);
});
