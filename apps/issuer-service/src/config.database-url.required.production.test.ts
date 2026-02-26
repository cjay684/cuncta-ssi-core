import { strict as assert } from "node:assert";

const run = async () => {
  // Import with a non-production env so module init (`config = parseConfig(process.env)`) cannot fail.
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = "test";
  try {
    const { parseConfig } = await import("./config.js");
    const env = {
      NODE_ENV: "production",
      PORT: "3002",
      DEV_MODE: "false",
      BACKUP_RESTORE_MODE: "false",
      PUBLIC_SERVICE: "true",
      TRUST_PROXY: "true",
      HEDERA_NETWORK: "testnet",
      ALLOW_MAINNET: "false",
      ISSUER_BASE_URL: "http://issuer.test",
      DID_SERVICE_BASE_URL: "http://did.test",
      // Production requires OID4VCI signing JWK if OID4VCI is enabled (default true).
      OID4VCI_TOKEN_SIGNING_JWK: JSON.stringify({
        kty: "OKP",
        crv: "Ed25519",
        x: "test",
        d: "test",
        alg: "EdDSA",
        kid: "oid4vci-token-1"
      }),
      OID4VCI_TOKEN_SIGNING_BOOTSTRAP: "false"
      // Intentionally omit DATABASE_URL.
    } as NodeJS.ProcessEnv;

    let threw = false;
    try {
      parseConfig(env);
    } catch (error) {
      threw = true;
      assert.ok(
        error instanceof Error && error.message === "database_url_required_in_production",
        `expected database_url_required_in_production, got: ${error instanceof Error ? error.message : String(error)}`
      );
    }
    assert.equal(threw, true, "expected parseConfig() to throw when DATABASE_URL is missing in production");
  } finally {
    process.env.NODE_ENV = previousNodeEnv;
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

