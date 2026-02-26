import { strict as assert } from "node:assert";

const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
  NODE_ENV: "production",
  ALLOW_INSECURE_DEV_AUTH: "true",
  // Ensure this test is deterministic and does not depend on a developer's `.env`.
  PUBLIC_SERVICE: "false",
  TRUST_PROXY: "true",
  SERVICE_BIND_ADDRESS: "127.0.0.1",
  AUTO_MIGRATE: "false",
  STRICT_DB_ROLE: "true",
  ENFORCE_HTTPS_INTERNAL: "false",
  ALLOW_LEGACY_SERVICE_JWT_SECRET: "false",
  HEDERA_NETWORK: "testnet",
  ALLOW_MAINNET: "false",
  BREAK_GLASS_DISABLE_STRICT: "false",
  ISSUER_SERVICE_BASE_URL: "http://issuer.test",
  POLICY_SERVICE_BASE_URL: "http://policy.test",
  DID_SERVICE_BASE_URL: "http://did.test",
  // Production requires request signing enabled -> a signing key must be present.
  VERIFIER_SIGN_OID4VP_REQUEST: "true",
  VERIFIER_SIGNING_JWK: JSON.stringify({
    kty: "OKP",
    crv: "Ed25519",
    x: "test",
    d: "test",
    alg: "EdDSA",
    kid: "verifier-1"
  }),
  // Avoid production startup failure from env-provided issuer JWKS.
  ISSUER_JWKS: undefined,
  // This test is about the insecure auth gate, not service auth.
  SERVICE_JWT_SECRET: undefined,
  SERVICE_JWT_SECRET_VERIFIER: undefined,
  SERVICE_JWT_SECRET_NEXT: undefined,
  PSEUDONYMIZER_PEPPER: "test-pepper"
};

const run = async () => {
  const previousValues = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(TEST_ENV_OVERRIDES)) {
    previousValues.set(key, process.env[key]);
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    const { config } = await import("./config.js");
    config.TRUST_PROXY = true;
    const { buildServer } = await import("./server.js");
    buildServer();
    assert.fail("Expected buildServer to throw in production insecure mode");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert.equal(message, "insecure_dev_auth_not_allowed");
  } finally {
    for (const [key, value] of previousValues.entries()) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
