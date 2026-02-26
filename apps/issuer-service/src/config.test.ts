import { strict as assert } from "node:assert";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);

const run = async () => {
  // Ensure this test is deterministic and does not depend on a developer's `.env`
  // (importing `./config.js` evaluates `parseConfig(process.env)` at module init).
  const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
    NODE_ENV: "test",
    HEDERA_NETWORK: "testnet",
    ALLOW_MAINNET: "false",
    ISSUER_BASE_URL: "http://issuer.test",
    DID_SERVICE_BASE_URL: "http://did.test",
    ISSUER_DID: "did:example:issuer",
    // Keep config importable even if a dev `.env` sets production-only fields.
    OID4VCI_TOKEN_SIGNING_JWK: undefined,
    OID4VCI_TOKEN_SIGNING_BOOTSTRAP: "false"
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
  process.env.SERVICE_JWT_SECRET = TEST_SECRET_HEX;
  process.env.SERVICE_JWT_SECRET_ISSUER = TEST_SECRET_HEX;
  process.env.SERVICE_JWT_SECRET_FORMAT_STRICT = "false";

  try {
    const { parseConfig } = await import("./config.js");
    const env = {
      NODE_ENV: "test",
      PORT: "3002",
      HEDERA_NETWORK: "testnet",
      ISSUER_BASE_URL: "http://issuer.test",
      DID_SERVICE_BASE_URL: "http://did.test",
      ANCHOR_OUTBOX_PROCESSING_TIMEOUT_MS: "1000",
      ANCHOR_WORKER_POLL_MS: "50",
      AURA_WORKER_POLL_MS: "999999",
      OUTBOX_BATCH_SIZE: "500",
      CLEANUP_WORKER_POLL_MS: "10",
      RETENTION_VERIFICATION_CHALLENGES_DAYS: "0",
      RETENTION_RATE_LIMIT_EVENTS_DAYS: "999",
      RETENTION_OBLIGATION_EVENTS_DAYS: "0",
      RETENTION_AURA_SIGNALS_DAYS: "999",
      RETENTION_AUDIT_LOGS_DAYS: "3",
      PRIVACY_CHALLENGE_TTL_SECONDS: "5",
      PRIVACY_TOKEN_TTL_SECONDS: "99999"
    } as NodeJS.ProcessEnv;

    const parsed = parseConfig(env);
    assert.equal(parsed.ANCHOR_OUTBOX_PROCESSING_TIMEOUT_MS, 30_000);
    assert.equal(parsed.ANCHOR_WORKER_POLL_MS, 250);
    assert.equal(parsed.AURA_WORKER_POLL_MS, 30_000);
    assert.equal(parsed.OUTBOX_BATCH_SIZE, 200);
    assert.equal(parsed.CLEANUP_WORKER_POLL_MS, 60 * 1000);
    assert.equal(parsed.RETENTION_VERIFICATION_CHALLENGES_DAYS, 1);
    assert.equal(parsed.RETENTION_RATE_LIMIT_EVENTS_DAYS, 90);
    assert.equal(parsed.RETENTION_OBLIGATION_EVENTS_DAYS, 1);
    assert.equal(parsed.RETENTION_AURA_SIGNALS_DAYS, 365);
    assert.equal(parsed.RETENTION_AUDIT_LOGS_DAYS, 7);
    assert.equal(parsed.PRIVACY_CHALLENGE_TTL_SECONDS, 30);
    assert.equal(parsed.PRIVACY_TOKEN_TTL_SECONDS, 3600);
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

try {
  run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
