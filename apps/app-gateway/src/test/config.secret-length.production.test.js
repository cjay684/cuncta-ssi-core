import { strict as assert } from "node:assert";

process.env.NODE_ENV = "production";
process.env.HEDERA_NETWORK = "testnet";
process.env.DID_SERVICE_BASE_URL = "http://localhost:3001";
process.env.ISSUER_SERVICE_BASE_URL = "http://localhost:3002";
process.env.VERIFIER_SERVICE_BASE_URL = "http://localhost:3003";
process.env.POLICY_SERVICE_BASE_URL = "http://localhost:3004";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.SERVICE_JWT_SECRET = "short-secret";
process.env.PSEUDONYMIZER_PEPPER = "pepper-test-123456";
process.env.USER_PAYS_HANDOFF_SECRET = "user-pays-handoff-secret-12345678901234567890";

try {
  await import("../config.ts");
  assert.fail("Expected config parse to fail for short secrets in production");
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  assert.ok(message.includes("SERVICE_JWT_SECRET") || message.includes("32"));
}
