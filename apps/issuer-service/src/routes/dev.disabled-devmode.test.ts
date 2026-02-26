import { strict as assert } from "node:assert";

process.env.NODE_ENV = "development";
process.env.DEV_MODE = "false";
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
process.env.POLICY_SIGNING_JWK = JSON.stringify({
  kty: "OKP",
  crv: "Ed25519",
  x: "test",
  d: "test",
  alg: "EdDSA",
  kid: "policy-1"
});

const run = async () => {
  const { config } = await import("../config.js");
  config.NODE_ENV = "development";
  config.DEV_MODE = false;
  config.SERVICE_BIND_ADDRESS = "127.0.0.1";
  config.ISSUER_BASE_URL = "http://issuer.test";
  config.ISSUER_DID = "did:example:issuer";
  config.ISSUER_JWK = process.env.ISSUER_JWK ?? "";
  config.PSEUDONYMIZER_PEPPER = "test-pepper";
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK ?? "";
  const { buildServer } = await import("../server.js");
  const app = buildServer();
  const response = await app.inject({
    method: "POST",
    url: "/v1/dev/issue",
    payload: { subjectDid: "did:example:holder", vct: "cuncta.marketplace.seller_good_standing" }
  });
  assert.equal(
    response.statusCode,
    404,
    `expected 404, got ${response.statusCode} (${response.body})`
  );
  await app.close();
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
