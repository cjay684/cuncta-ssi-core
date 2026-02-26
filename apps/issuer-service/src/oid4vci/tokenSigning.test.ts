import { strict as assert } from "node:assert";

const run = async () => {
  const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
    NODE_ENV: "test",
    HEDERA_NETWORK: "testnet",
    ALLOW_MAINNET: "false",
    ISSUER_BASE_URL: "http://issuer.test",
    DID_SERVICE_BASE_URL: "http://did.test",
    // Allow bootstrap signing in dev/test only.
    OID4VCI_TOKEN_SIGNING_BOOTSTRAP: "true",
    OID4VCI_TOKEN_SIGNING_JWK: undefined
  };
  const previousValues = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(TEST_ENV_OVERRIDES)) {
    previousValues.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }

  const { signOid4vciAccessToken, verifyOid4vciAccessTokenEdDSA, getOid4vciTokenJwks } =
    await import("./tokenSigning.js");

  const issuer = "http://issuer.example";
  const jwks = await getOid4vciTokenJwks();

  const token = await signOid4vciAccessToken({
    issuer,
    audience: issuer,
    ttlSeconds: 60,
    scope: ["credential"]
  });
  assert.ok(token.includes("."), "token should be JWT format");

  await verifyOid4vciAccessTokenEdDSA({
    token,
    issuerBaseUrl: issuer,
    requiredScopes: ["credential"],
    jwks
  });

  const noScope = await signOid4vciAccessToken({
    issuer,
    audience: issuer,
    ttlSeconds: 60,
    scope: []
  });
  let rejected = false;
  try {
    await verifyOid4vciAccessTokenEdDSA({
      token: noScope,
      issuerBaseUrl: issuer,
      requiredScopes: ["credential"],
      jwks
    });
  } catch (error) {
    rejected = error instanceof Error && error.message === "oid4vci_token_missing_required_scope";
  }
  assert.equal(rejected, true, "token missing scope should be rejected");

  for (const [key, value] of previousValues.entries()) {
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
