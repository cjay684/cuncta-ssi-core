import { strict as assert } from "node:assert";
import { SignJWT } from "jose";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);

process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.DEV_MODE = "true";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.ISSUER_DID = "did:example:issuer";
process.env.SERVICE_JWT_SECRET = TEST_SECRET_HEX;
process.env.SERVICE_JWT_SECRET_ISSUER = process.env.SERVICE_JWT_SECRET;
process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";
process.env.SERVICE_JWT_AUDIENCE_ISSUER = "cuncta.service.issuer";
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

const buildServiceToken = async (scope: string) => {
  const key = new TextEncoder().encode(process.env.SERVICE_JWT_SECRET ?? "");
  return new SignJWT({ sub: "app-gateway", scope })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("app-gateway")
    .setSubject("app-gateway")
    .setAudience(
      process.env.SERVICE_JWT_AUDIENCE_ISSUER ??
        process.env.SERVICE_JWT_AUDIENCE ??
        "cuncta-internal"
    )
    .setExpirationTime("5m")
    .sign(key);
};

const run = async () => {
  const { config } = await import("../config.js");
  config.SERVICE_JWT_SECRET_ISSUER = process.env.SERVICE_JWT_SECRET_ISSUER ?? "";
  config.SERVICE_JWT_AUDIENCE_ISSUER = process.env.SERVICE_JWT_AUDIENCE_ISSUER ?? "";
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK ?? "";
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET ?? "";

  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");

  const app = buildServer();
  await app.ready();
  const db = await getDb();

  // Ensure no rule integrity noise for this auth test.
  await db("aura_rules").update({ enabled: false });

  const url = "/v1/reputation/recompute/did:example:alice";

  const noAuth = await app.inject({ method: "POST", url });
  assert.equal(noAuth.statusCode, 401);

  const wrongScope = await app.inject({
    method: "POST",
    url,
    headers: { authorization: `Bearer ${await buildServiceToken("issuer:reputation_ingest")}` }
  });
  assert.equal(wrongScope.statusCode, 403);

  const ok = await app.inject({
    method: "POST",
    url,
    headers: { authorization: `Bearer ${await buildServiceToken("issuer:reputation_recompute")}` }
  });
  assert.equal(ok.statusCode, 200);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

