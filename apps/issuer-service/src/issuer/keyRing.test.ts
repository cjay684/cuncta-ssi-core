import { strict as assert } from "node:assert";

process.env.NODE_ENV = "test";
process.env.HEDERA_NETWORK = "testnet";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.ISSUER_KEYS_ALLOW_DB_PRIVATE = "true";
process.env.ANCHOR_AUTH_SECRET = "test-anchor-auth-secret-please-rotate";

const run = async () => {
  const { getDb } = await import("../db.js");
  const { rotateIssuerKey, revokeIssuerKey } = await import("./keyRing.js");
  const { closeDb } = await import("@cuncta/db");

  const db = await getDb();
  const previousActive = await db("issuer_keys").where({ status: "ACTIVE" }).select("kid");

  const { kid } = await rotateIssuerKey();
  const activeRow = await db("issuer_keys").where({ kid }).first();
  assert.equal(activeRow?.status, "ACTIVE");
  assert.ok(activeRow?.public_jwk);
  assert.ok(activeRow?.private_jwk);

  await revokeIssuerKey(kid);
  const revokedRow = await db("issuer_keys").where({ kid }).first();
  assert.equal(revokedRow?.status, "REVOKED");

  if (previousActive.length > 0) {
    await db("issuer_keys")
      .whereIn(
        "kid",
        previousActive.map((row) => row.kid)
      )
      .update({ status: "ACTIVE", updated_at: new Date().toISOString() });
  }

  await db("issuer_keys").where({ kid }).del();
  await closeDb(db);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
