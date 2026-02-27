import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { getZkStatement } from "@cuncta/zk-registry";
import { sha256ToField } from "@cuncta/zk-proof-groth16-bn254";

const b64u = (input: string) => Buffer.from(input, "utf8").toString("base64url");
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const setDeterministicTestEnv = () => {
  // Keep tests deterministic regardless of developer `.env`.
  process.env.NODE_ENV = "test";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.ALLOW_MAINNET = "false";
  process.env.ISSUER_SERVICE_BASE_URL = "http://issuer.test";
  process.env.POLICY_SERVICE_BASE_URL = "http://policy.test";
  process.env.PUBLIC_SERVICE = "false";
  process.env.TRUST_PROXY = "false";
  // Avoid env-provided production-only config from a developer `.env`.
  delete process.env.ISSUER_JWKS;
};

test("zk predicates: commitment mismatch fails closed", async () => {
  setDeterministicTestEnv();
  const { verifyRequiredZkPredicates } = await import("./verifyZkPredicates.js");
  const statement = await getZkStatement("age_gte_v1");
  assert.ok(statement.available);

  const serverDay = Math.floor(Date.now() / 86_400_000);
  const nonce = `nonce-${randomUUID()}-1234567890`;
  const audience = "origin:https://example.test";
  const currentDay = serverDay;

  const requestPayload = {
    iss: "https://gateway.test",
    aud: "https://wallet.test",
    nonce,
    audience,
    zk_context: { current_day: currentDay }
  };
  const requestJwt = `${b64u(JSON.stringify({ alg: "none", typ: "oid4vp-request+jwt" }))}.${b64u(
    JSON.stringify(requestPayload)
  )}.`;
  const requestHash = sha256Hex(requestJwt);

  // Construct a structurally-valid proof entry without doing full proving.
  // This test targets commitment linkage checks and must still fail closed.
  const publicSignals = [
    "123", // dob_commitment (public input)
    "18", // min_age
    String(currentDay), // current_day
    sha256ToField(nonce).toString(),
    sha256ToField(audience).toString(),
    sha256ToField(requestHash).toString()
  ];

  const zkProofs = [
    {
      statement_id: "age_gte_v1",
      version: statement.definition.version,
      proof_system: statement.definition.proof_system,
      public_signals: publicSignals,
      proof: {} // proof is not evaluated when earlier checks already deny
    }
  ];

  const ok = await verifyRequiredZkPredicates({
    requiredPredicates: [{ id: "age_gte_v1", params: { min_age: 18 } }],
    zkProofs,
    requestHash,
    nonce,
    audience,
    requestJwt,
    claims: {
      dob_commitment: "999",
      commitment_scheme_version: "poseidon_v1_bn254_ds1"
    },
    expectedVct: "age_credential_v1"
  });
  assert.equal(ok.ok, false);
  assert.ok(ok.reasons.includes("zk_commitment_mismatch"));
});

test("zk predicates: commitment scheme mismatch is denied", async () => {
  setDeterministicTestEnv();
  const { verifyRequiredZkPredicates } = await import("./verifyZkPredicates.js");
  const statement = await getZkStatement("age_gte_v1");
  assert.ok(statement.available);

  const serverDay = Math.floor(Date.now() / 86_400_000);
  const nonce = `nonce-${randomUUID()}-1234567890`;
  const audience = "origin:https://example.test";
  const currentDay = serverDay;

  const requestJwt = `${b64u(JSON.stringify({ alg: "none", typ: "oid4vp-request+jwt" }))}.${b64u(
    JSON.stringify({ nonce, audience, zk_context: { current_day: currentDay } })
  )}.`;
  const requestHash = sha256Hex(requestJwt);

  const publicSignals = [
    "123",
    "18",
    String(currentDay),
    sha256ToField(nonce).toString(),
    sha256ToField(audience).toString(),
    sha256ToField(requestHash).toString()
  ];

  const zkProofs = [
    {
      statement_id: "age_gte_v1",
      version: statement.definition.version,
      proof_system: statement.definition.proof_system,
      public_signals: publicSignals,
      proof: {}
    }
  ];

  const ok = await verifyRequiredZkPredicates({
    requiredPredicates: [{ id: "age_gte_v1", params: { min_age: 18 } }],
    zkProofs,
    requestHash,
    nonce,
    audience,
    requestJwt,
    claims: {
      dob_commitment: "123",
      commitment_scheme_version: "poseidon_v1_bn254"
    },
    expectedVct: "age_credential_v1"
  });
  assert.equal(ok.ok, false);
  assert.ok(ok.reasons.includes("commitment_scheme_mismatch"));
});
