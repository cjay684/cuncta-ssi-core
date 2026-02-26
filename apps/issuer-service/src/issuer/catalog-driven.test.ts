import { strict as assert } from "node:assert";
import { randomUUID } from "node:crypto";
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

  const { getDb } = await import("../db.js");
  const { issueCredential } = await import("./issuance.js");

  const vct = `cuncta.test.${randomUUID()}`;
  const db = await getDb();
  await db("credential_types").insert({
    vct,
    json_schema: JSON.stringify({
      type: "object",
      properties: { flag: { type: "boolean" } },
      required: ["flag"],
      additionalProperties: false
    }),
    sd_defaults: JSON.stringify(["flag"]),
    display: JSON.stringify({
      title: "Test Flag",
      claims: [{ path: "flag", label: "Flag" }]
    }),
    purpose_limits: JSON.stringify({ actions: ["marketplace.list_item"] }),
    presentation_templates: JSON.stringify({ required_disclosures: ["flag"] }),
    revocation_config: JSON.stringify({
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 256
    })
  });

  const result = await issueCredential({
    subjectDid: "did:example:holder",
    vct,
    claims: { flag: true }
  });

  assert.ok(result.credential.length > 20);
  assert.equal(result.credentialStatus.statusPurpose, "revocation");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
