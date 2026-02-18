import { strict as assert } from "node:assert";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);
const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
  NODE_ENV: "production",
  ALLOW_INSECURE_DEV_AUTH: "true",
  TRUST_PROXY: "true",
  PUBLIC_SERVICE: "false",
  SERVICE_BIND_ADDRESS: "127.0.0.1",
  AUTO_MIGRATE: "false",
  STRICT_DB_ROLE: "true",
  ENFORCE_HTTPS_INTERNAL: "false",
  ALLOW_LEGACY_SERVICE_JWT_SECRET: "false",
  ISSUER_BASE_URL: "http://issuer.test",
  ISSUER_DID: "did:example:issuer",
  ISSUER_JWK: JSON.stringify({
    kty: "OKP",
    crv: "Ed25519",
    x: "test",
    d: "test",
    alg: "EdDSA",
    kid: "issuer-1"
  }),
  PSEUDONYMIZER_PEPPER: "test-pepper",
  SERVICE_JWT_SECRET: TEST_SECRET_HEX,
  SERVICE_JWT_SECRET_ISSUER: TEST_SECRET_HEX,
  SERVICE_JWT_SECRET_NEXT: undefined
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
    config.NODE_ENV = "production";
    config.TRUST_PROXY = true;
    config.ALLOW_INSECURE_DEV_AUTH = true;
    config.SERVICE_BIND_ADDRESS = "127.0.0.1";
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
