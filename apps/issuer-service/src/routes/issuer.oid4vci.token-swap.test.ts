import { test } from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair } from "jose";

process.env.NODE_ENV = "test";
process.env.DEV_MODE = "true";
process.env.HEDERA_NETWORK = "testnet";
process.env.ALLOW_MAINNET = "false";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.ISSUER_ENABLE_OID4VCI = "true";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "issuer-test-pepper-123456";
process.env.SERVICE_JWT_SECRET =
  process.env.SERVICE_JWT_SECRET ?? "0123456789abcdef".repeat(4);
process.env.SERVICE_JWT_SECRET_ISSUER = process.env.SERVICE_JWT_SECRET;
process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";
process.env.SERVICE_JWT_AUDIENCE_ISSUER = "cuncta.service.issuer";
process.env.ISSUER_KEYS_BOOTSTRAP = "true";
process.env.OID4VCI_TOKEN_SIGNING_BOOTSTRAP = "true";

test("OID4VCI token swapping is blocked (token.vct must match requested credential_configuration_id)", async () => {
  // Ensure issuer can boot (signing keys).
  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "test-issuer";
  jwk.alg = "EdDSA";
  jwk.crv = "Ed25519";
  jwk.kty = "OKP";
  process.env.ISSUER_JWK = JSON.stringify(jwk);

  const { buildServer } = await import("../server.js");
  const { createPreauthCode } = await import("../oid4vci/preauth.js");

  const app = buildServer();
  await app.ready();

  const cfgA = "sdjwt:cuncta.test.swap_a";
  const cfgB = "sdjwt:cuncta.test.swap_b";
  const offerA = await createPreauthCode({ vct: cfgA, ttlSeconds: 120, txCode: null, scope: null });
  await createPreauthCode({ vct: cfgB, ttlSeconds: 120, txCode: null, scope: null });

  const tokenRes = await app.inject({
    method: "POST",
    url: "/token",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      "pre-authorized_code": offerA.preAuthorizedCode
    }).toString()
  });
  assert.equal(tokenRes.statusCode, 200);
  const tokenPayload = tokenRes.json() as { access_token?: string };
  assert.ok(tokenPayload.access_token);

  // Attempt to request cfgB using a token bound to cfgA.
  const credentialRes = await app.inject({
    method: "POST",
    url: "/credential",
    headers: { authorization: `Bearer ${tokenPayload.access_token}` },
    payload: {
      credential_configuration_id: cfgB
    }
  });
  assert.equal(credentialRes.statusCode, 401);
  await app.close();
});

