import { strict as assert } from "node:assert";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);

process.env.NODE_ENV = "development";
process.env.ALLOW_INSECURE_DEV_AUTH = "true";
process.env.SERVICE_BIND_ADDRESS = "127.0.0.1";
process.env.HEDERA_NETWORK = "testnet";
process.env.ALLOW_MAINNET = "false";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DID_SERVICE_BASE_URL = "http://did.test";
process.env.ISSUER_DID = "did:example:issuer";
process.env.ISSUER_JWK = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  x: "test",
  d: "test",
  alg: "EdDSA",
  kid: "issuer-1"
});
process.env.PSEUDONYMIZER_PEPPER = "test-pepper";
process.env.SERVICE_JWT_SECRET = TEST_SECRET_HEX;
process.env.SERVICE_JWT_SECRET_ISSUER = TEST_SECRET_HEX;

const run = async () => {
  const { buildServer } = await import("./server.js");
  const app = buildServer();
  assert.ok(app);
  await app.close();
};

run().catch((error) => {
  let msg = "";
  if (error instanceof Error) {
    msg = error.message;
  } else {
    try {
      msg = JSON.stringify(error);
    } catch {
      msg = "[non-Error thrown]";
    }
  }
  console.error(msg);
  // Also log the raw object for debugging; some thrown objects are non-enumerable.
  // eslint-disable-next-line no-console
  console.error(error);
  process.exit(1);
});
