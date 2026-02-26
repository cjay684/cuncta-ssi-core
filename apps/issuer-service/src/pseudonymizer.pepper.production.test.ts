import { strict as assert } from "node:assert";
import { spawnSync } from "node:child_process";

const run = async () => {
  const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);
  const script = [
    "import('./src/pseudonymizer.ts')",
    ".then(({ getDidHashes }) => {",
    "  try {",
    "    getDidHashes('did:example:missing-pepper');",
    "    process.exit(0);",
    "  } catch (error) {",
    "    console.error(error instanceof Error ? error.message : String(error));",
    "    process.exit(1);",
    "  }",
    "})",
    ".catch((error) => {",
    "  console.error(error instanceof Error ? error.message : String(error));",
    "  process.exit(1);",
    "});"
  ].join("");

  const result = spawnSync(
    process.execPath,
    ["--import", "tsx", "--input-type=module", "-e", script],
    {
      env: {
        ...process.env,
        NODE_ENV: "production",
        TRUST_PROXY: "true",
        ISSUER_BASE_URL: "http://issuer.test",
        ISSUER_DID: "did:example:issuer",
        ISSUER_JWK: JSON.stringify({
          kty: "OKP",
          crv: "Ed25519",
          x: "test",
          d: "test",
          alg: "EdDSA",
          kid: "issuer-1"
        }),
        OID4VCI_TOKEN_SIGNING_JWK: JSON.stringify({
          kty: "OKP",
          crv: "Ed25519",
          x: "test",
          d: "test",
          alg: "EdDSA",
          kid: "oid4vci-token-1"
        }),
        OID4VCI_TOKEN_SIGNING_BOOTSTRAP: "false",
        SERVICE_JWT_SECRET: TEST_SECRET_HEX,
        SERVICE_JWT_SECRET_ISSUER: TEST_SECRET_HEX,
        PSEUDONYMIZER_PEPPER: ""
      },
      encoding: "utf8"
    }
  );

  assert.equal(result.status, 1);
  const combinedOutput = `${result.stderr ?? ""}${result.stdout ?? ""}`;
  assert.ok(combinedOutput.includes("pseudonymizer_pepper_missing"));
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
