import { strict as assert } from "node:assert";
import { decodeJwt, exportJWK, generateKeyPair } from "jose";
import { issueSdJwtVc, verifySdJwtVc } from "./index.js";

const run = async () => {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  privateJwk.kid = "test-1";
  privateJwk.alg = "EdDSA";
  privateJwk.crv = "Ed25519";
  privateJwk.kty = "OKP";
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = privateJwk.kid;
  publicJwk.alg = privateJwk.alg;
  publicJwk.crv = privateJwk.crv;
  publicJwk.kty = privateJwk.kty;

  const token = await issueSdJwtVc({
    issuerJwk: privateJwk,
    payload: {
      iss: "did:example:issuer",
      sub: "did:example:holder",
      vct: "cuncta.age_over_18",
      age_over_18: true
    },
    selectiveDisclosure: ["age_over_18"],
    typMode: "strict"
  });

  const [jwt, disclosure] = token.split("~");
  assert.ok(disclosure, "disclosure_missing");
  const payload = decodeJwt(jwt);
  assert.ok(Array.isArray(payload._sd), "sd_digests_missing");
  assert.ok(payload._sd?.length, "sd_digests_empty");

  const verified = await verifySdJwtVc({
    token,
    jwks: { keys: [publicJwk] }
  });
  assert.equal(verified.claims.age_over_18, true);
  const payloadRecord = verified.payload as Record<string, unknown>;
  assert.equal(payloadRecord.age_over_18, undefined);

  const tampered = token.replace(disclosure, `${disclosure}x`);
  let threw = false;
  try {
    await verifySdJwtVc({ token: tampered, jwks: { keys: [publicJwk] } });
  } catch {
    threw = true;
  }
  assert.ok(threw, "tampered_disclosure_should_fail");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
