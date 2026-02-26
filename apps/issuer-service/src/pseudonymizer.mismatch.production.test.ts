import { strict as assert } from "node:assert";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);

process.env.NODE_ENV = "production";
process.env.PSEUDONYMIZER_PEPPER = "pepper-a";
process.env.PSEUDONYMIZER_ALLOW_LEGACY = "false";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DID_SERVICE_BASE_URL = "http://did.test";
process.env.ISSUER_DID = "did:example:issuer";
process.env.ISSUER_JWK = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  x: "test",
  d: "test",
  alg: "EdDSA",
  kid: "issuer-1"
});
process.env.OID4VCI_TOKEN_SIGNING_JWK = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  x: "test",
  d: "test",
  alg: "EdDSA",
  kid: "oid4vci-token-1"
});
process.env.OID4VCI_TOKEN_SIGNING_BOOTSTRAP = "false";
process.env.SERVICE_JWT_SECRET_ISSUER = TEST_SECRET_HEX;
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

const run = async () => {
  const { ensurePseudonymizerConsistency } = await import("./pseudonymizer.js");
  const { getDb } = await import("./db.js");
  const db = await getDb();
  await db("system_metadata").del();

  await ensurePseudonymizerConsistency();

  await db("system_metadata")
    .where({ key: "pseudonymizer_fingerprint" })
    .update({ value: "mismatch", updated_at: new Date().toISOString() });

  let threw = false;
  try {
    await ensurePseudonymizerConsistency();
  } catch (error) {
    threw = true;
    const message = error instanceof Error ? error.message : String(error);
    assert.equal(message, "pseudonymizer_mismatch");
  }
  assert.equal(threw, true);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
