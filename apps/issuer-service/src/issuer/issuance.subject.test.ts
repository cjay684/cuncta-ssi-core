import { strict as assert } from "node:assert";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";

process.env.NODE_ENV = "test";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.ISSUER_DID = "did:example:issuer";
process.env.PSEUDONYMIZER_PEPPER = "pepper-test-123456";
process.env.PSEUDONYMIZER_ALLOW_LEGACY = "true";
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
  const { getDidHashes } = await import("../pseudonymizer.js");
  const db = await getDb();
  await db("issuance_events").del();
  await db("status_list_versions").del();
  await db("status_lists").del();
  await db("privacy_tombstones").del();

  const subjectDid = "did:example:holder:subject";
  const result = await issueCredential({
    subjectDid,
    vct: "cuncta.marketplace.seller_good_standing",
    claims: {
      seller_good_standing: true,
      domain: "marketplace",
      as_of: new Date().toISOString(),
      tier: "bronze"
    }
  });

  const jwtPart = result.credential.split("~")[0] ?? "";
  const payload = decodeJwt(jwtPart) as Record<string, unknown>;
  assert.equal(payload.sub, subjectDid);

  const hashes = getDidHashes(subjectDid);
  await db("privacy_tombstones").insert({
    did_hash: hashes.primary,
    erased_at: new Date().toISOString()
  });
  let rejected = false;
  try {
    await issueCredential({
      subjectDid,
      vct: "cuncta.marketplace.seller_good_standing",
      claims: {
        seller_good_standing: true,
        domain: "marketplace",
        as_of: new Date().toISOString(),
        tier: "bronze"
      }
    });
  } catch (error) {
    rejected = error instanceof Error && error.message === "privacy_erased";
  }
  assert.equal(rejected, true, "tombstoned subject should be blocked");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
