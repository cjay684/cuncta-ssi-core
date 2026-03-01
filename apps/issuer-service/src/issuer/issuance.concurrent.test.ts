import { strict as assert } from "node:assert";
import { exportJWK, generateKeyPair } from "jose";

process.env.NODE_ENV = "test";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.ISSUER_DID = "did:example:issuer";
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
process.env.ISSUER_KEYS_BOOTSTRAP = "true";

const run = async () => {
  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "test-issuer";
  jwk.alg = "EdDSA";
  jwk.crv = "Ed25519";
  jwk.kty = "OKP";
  process.env.ISSUER_JWK = JSON.stringify(jwk);

  const { config } = await import("../config.js");
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;
  config.ISSUER_KEYS_BOOTSTRAP = true;
  config.ISSUER_JWK = process.env.ISSUER_JWK;

  const { issueCredential } = await import("./issuance.js");
  const { getDb } = await import("../db.js");
  const db = await getDb();
  await db("issuance_events").del();
  await db("status_list_versions").del();
  await db("status_lists").del();

  const results = [];
  for (let index = 0; index < 20; index += 1) {
    results.push(
      await issueCredential({
        subjectDid: `did:example:holder:${index}`,
        vct: "cuncta.age_over_18",
        claims: {
          age_over_18: true
        }
      })
    );
  }

  const indices = results.map((result) => Number(result.credentialStatus.statusListIndex));
  const unique = new Set(indices);
  assert.equal(unique.size, indices.length);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
