import assert from "node:assert/strict";
import { exportJWK, generateKeyPair } from "jose";

const run = async () => {
  // Keep tests deterministic regardless of developer `.env`.
  process.env.HEDERA_NETWORK = "testnet";
  process.env.ALLOW_MAINNET = "false";

  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "policy-test-1";
  process.env.POLICY_SIGNING_JWK = JSON.stringify(jwk);
  process.env.POLICY_SIGNING_BOOTSTRAP = "true";
  process.env.ANCHOR_AUTH_SECRET = "test-anchor-secret";

  const { computePolicyHash, ensurePolicyIntegrity } = await import("./integrity.js");

  const row = {
    policy_id: "policy.test",
    action_id: "policy.test.action",
    version: 1,
    enabled: true,
    logic: { requirements: [] },
    policy_hash: "",
    policy_signature: "invalid.signature"
  };
  row.policy_hash = computePolicyHash(row);

  await assert.rejects(async () => {
    await ensurePolicyIntegrity(row);
  }, /policy_integrity_failed/);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
