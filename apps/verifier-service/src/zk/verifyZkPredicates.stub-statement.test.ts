import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";

const b64u = (input: string) => Buffer.from(input, "utf8").toString("base64url");
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const setDeterministicTestEnv = () => {
  process.env.NODE_ENV = "test";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.ALLOW_MAINNET = "false";
  delete process.env.ISSUER_JWKS;
};

test("zk predicates: stub statement is rejected gracefully (data-driven)", async () => {
  setDeterministicTestEnv();
  const { verifyRequiredZkPredicates } = await import("./verifyZkPredicates.js");

  const nonce = `nonce-${randomUUID()}-1234567890`;
  const audience = "origin:https://example.test";
  const requestPayload = {
    iss: "https://gateway.test",
    aud: "https://wallet.test",
    nonce,
    audience,
    zk_context: {}
  };
  const requestJwt = `${b64u(JSON.stringify({ alg: "none", typ: "oid4vp-request+jwt" }))}.${b64u(
    JSON.stringify(requestPayload)
  )}.`;
  const requestHash = sha256Hex(requestJwt);

  const out = await verifyRequiredZkPredicates({
    requiredPredicates: [{ id: "tier_gte_v1", params: { min_tier: 1 } }],
    zkProofs: [
      {
        statement_id: "tier_gte_v1",
        version: "0.1.0",
        proof_system: "groth16_bn254",
        public_signals: ["1", "1", "2", "3", "4"],
        proof: {}
      }
    ],
    requestHash,
    nonce,
    audience,
    requestJwt,
    claims: {},
    expectedVct: undefined
  });

  assert.equal(out.ok, false);
  assert.ok(out.reasons.includes("zk_statement_unavailable"));
});

