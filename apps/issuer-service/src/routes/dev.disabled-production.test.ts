import { strict as assert } from "node:assert";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);

process.env.NODE_ENV = "production";
process.env.DEV_MODE = "true";
process.env.TRUST_PROXY = "true";
process.env.SERVICE_BIND_ADDRESS = "127.0.0.1";
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
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "test-pepper";
process.env.POLICY_SIGNING_JWK = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  x: "test",
  d: "test",
  alg: "EdDSA",
  kid: "policy-1"
});
process.env.SERVICE_JWT_SECRET = TEST_SECRET_HEX;
process.env.SERVICE_JWT_SECRET_ISSUER = TEST_SECRET_HEX;
process.env.SURFACE_REGISTRY_PUBLIC_KEY =
  process.env.SURFACE_REGISTRY_PUBLIC_KEY ??
  "eyJjcnYiOiJFZDI1NTE5IiwieCI6ImZtZXJOMk9uM2Rzck00OVhaS2hBQWVHT2VuaWM2SkpqaVhaTmhrQXphV3MiLCJrdHkiOiJPS1AiLCJhbGciOiJFZERTQSIsImtpZCI6InN1cmZhY2UtcmVnaXN0cnktc3NpLTEifQ";

const run = async () => {
  try {
    const { getDb } = await import("../db.js");
    const db = await getDb();
    await db("system_metadata").where({ key: "pseudonymizer_fingerprint" }).del();
    const { buildServer } = await import("../server.js");
    const app = buildServer();
    const response = await app.inject({
      method: "POST",
      url: "/v1/dev/issue",
      payload: { subjectDid: "did:example:holder", vct: "cuncta.marketplace.seller_good_standing" }
    });
    assert.equal(response.statusCode, 404);
    await app.close();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`unexpected_startup_failure:${message}`);
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
