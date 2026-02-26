import { strict as assert } from "node:assert";
import { SignJWT } from "jose";
import { verifyServiceJwt } from "./serviceAuth.js";

const run = async () => {
  const secret = "super-secret-key";
  const goodAud = "cuncta.service.did";
  const badAud = "cuncta.service.issuer";
  const token = await new SignJWT({ scope: ["did:create_request"] })
    .setProtectedHeader({ alg: "HS256" })
    .setAudience(goodAud)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setIssuer("app-gateway")
    .setSubject("app-gateway")
    .sign(new TextEncoder().encode(secret));

  await verifyServiceJwt(token, {
    audience: goodAud,
    secret,
    issuer: "app-gateway",
    subject: "app-gateway",
    requiredScopes: ["did:create_request"]
  });

  let rejected = false;
  try {
    await verifyServiceJwt(token, { audience: badAud, secret });
  } catch {
    rejected = true;
  }
  assert.equal(rejected, true, "wrong audience should be rejected");

  rejected = false;
  try {
    await verifyServiceJwt(token, {
      audience: goodAud,
      secret: `${secret}-other`
    });
  } catch {
    rejected = true;
  }
  assert.equal(rejected, true, "wrong secret should be rejected");

  rejected = false;
  try {
    await verifyServiceJwt(token, {
      audience: goodAud,
      secret,
      issuer: "app-gateway",
      subject: "app-gateway",
      requiredScopes: ["issuer:internal_issue"]
    });
  } catch (error) {
    rejected = error instanceof Error && error.message === "jwt_missing_required_scope";
  }
  assert.equal(rejected, true, "wrong scope should be rejected");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
