import assert from "node:assert/strict";

// Unit-level invariants: dependency/integrity failures must not emit 5xx or oracle payloads.
// This keeps verifier safe even under accidental exposure, while gateway still normalizes publicly.

const run = async () => {
  const TEST_ENV_OVERRIDES: Record<string, string | undefined> = {
    NODE_ENV: "test",
    HEDERA_NETWORK: "testnet",
    ALLOW_MAINNET: "false",
    ISSUER_SERVICE_BASE_URL: "http://issuer.test",
    POLICY_SERVICE_BASE_URL: "http://policy.test",
    TRUST_PROXY: "false",
    PUBLIC_SERVICE: "false",
    SERVICE_JWT_SECRET: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    SERVICE_JWT_SECRET_VERIFIER: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ISSUER_JWKS: undefined
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
    const { __test__ } = await import("./verify.js");

    assert.deepEqual(__test__.dependencyFailureDeny(), {
      decision: "DENY",
      reasons: ["not_allowed"],
      obligationExecutionId: null,
      obligationsExecuted: []
    });
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
