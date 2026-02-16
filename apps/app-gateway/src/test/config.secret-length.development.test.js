import { strict as assert } from "node:assert";

process.env.NODE_ENV = "development";
process.env.HEDERA_NETWORK = "testnet";
process.env.DID_SERVICE_BASE_URL = "http://localhost:3001";
process.env.ISSUER_SERVICE_BASE_URL = "http://localhost:3002";
process.env.VERIFIER_SERVICE_BASE_URL = "http://localhost:3003";
process.env.POLICY_SERVICE_BASE_URL = "http://localhost:3004";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.SERVICE_JWT_SECRET = "test-secret-12345678901234567890123456789012";
process.env.SERVICE_JWT_SECRET_DID = "test-secret-12345678901234567890123456789012-did";
process.env.SERVICE_JWT_SECRET_ISSUER = "test-secret-12345678901234567890123456789012-issuer";
process.env.SERVICE_JWT_SECRET_VERIFIER = "test-secret-12345678901234567890123456789012-verifier";
process.env.PSEUDONYMIZER_PEPPER = "pepper-test-123456";
process.env.USER_PAYS_HANDOFF_SECRET = "user-pays-handoff-secret-12345678901234567890";

const { config } = await import("../config.ts");
assert.ok(config.SERVICE_JWT_SECRET);
