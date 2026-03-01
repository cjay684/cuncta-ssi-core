import { strict as assert } from "node:assert";

const run = async () => {
  const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
    NODE_ENV: "production",
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
    ISSUER_JWKS: undefined,
    SERVICE_JWT_SECRET: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    SERVICE_JWT_SECRET_VERIFIER: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    PSEUDONYMIZER_PEPPER: ""
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

  try {
    const { config } = await import("./config.js");
    config.NODE_ENV = "production";
    config.TRUST_PROXY = true;
    config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://issuer.test";
    config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://policy.test";
    config.SERVICE_JWT_SECRET_VERIFIER = process.env.SERVICE_JWT_SECRET_VERIFIER;
    config.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER;

    const { getDidHashes } = await import("./pseudonymizer.js");
    getDidHashes("did:example:missing-pepper");
    assert.fail("Expected pseudonymizer_pepper_missing");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    // #region agent log
    fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
      body: JSON.stringify({
        sessionId: "6783de",
        runId: process.env.DEBUG_RUN_ID ?? "baseline",
        hypothesisId: "H8",
        location: "apps/verifier-service/src/pseudonymizer.pepper.production.test.ts:catch",
        message: "captured thrown message for pseudonymizer production test",
        data: {
          thrownMessage: message,
          nodeEnv: process.env.NODE_ENV,
          hasPepperEnv: Boolean(process.env.PSEUDONYMIZER_PEPPER),
          hasServiceJwtSecretVerifier: Boolean(process.env.SERVICE_JWT_SECRET_VERIFIER)
        },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
    console.error("TEST_DIAG:pseudonymizer_production_error", message);
    assert.ok(message.includes("pseudonymizer_pepper_missing"));
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
