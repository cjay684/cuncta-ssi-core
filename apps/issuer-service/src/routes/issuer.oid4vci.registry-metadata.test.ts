import { test } from "node:test";
import assert from "node:assert/strict";

const setTestEnv = () => {
  process.env.NODE_ENV = "test";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.ALLOW_MAINNET = "false";
  process.env.DEV_MODE = "true";
  process.env.ISSUER_BASE_URL = "http://issuer.test";
  // Keep test offline: avoid DID bootstrap network calls during module init.
  process.env.ISSUER_DID = "did:example:issuer";
  process.env.ISSUER_ENABLE_OID4VCI = "true";
  process.env.ALLOW_EXPERIMENTAL_ZK = "true";
  // Avoid env-provided production-only config from a developer `.env`.
  delete process.env.ISSUER_JWKS;
};

test("issuer OID4VCI metadata: ZK credential configs derived from registry", async () => {
  setTestEnv();
  const { buildOid4vciIssuerMetadata } = await import("./issuer.js");
  const metadata = await buildOid4vciIssuerMetadata({
    issuerBaseUrl: process.env.ISSUER_BASE_URL ?? "http://issuer.test",
    allowExperimentalZk: true
  });
  const configs = (metadata.credential_configurations_supported ?? {}) as Record<string, unknown>;

  assert.ok(
    configs.age_credential_v1,
    "age_credential_v1 must be advertised when ALLOW_EXPERIMENTAL_ZK=true"
  );
  assert.equal((configs.age_credential_v1 as Record<string, unknown>).format, "dc+sd-jwt");

  assert.ok(
    !configs.tier_credential_v1,
    "stub statements must not appear as issuable credential configs"
  );
});
