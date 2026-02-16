import { strict as assert } from "node:assert";

const run = async () => {
  process.env.NODE_ENV = "production";
  process.env.TRUST_PROXY = "true";
  process.env.ISSUER_SERVICE_BASE_URL = "http://issuer.test";
  process.env.POLICY_SERVICE_BASE_URL = "http://policy.test";
  process.env.SERVICE_JWT_SECRET_VERIFIER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  process.env.PSEUDONYMIZER_PEPPER = "";

  const { config } = await import("./config.js");
  config.NODE_ENV = "production";
  config.TRUST_PROXY = true;
  config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://issuer.test";
  config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://policy.test";
  config.SERVICE_JWT_SECRET_VERIFIER = process.env.SERVICE_JWT_SECRET_VERIFIER;
  config.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER;

  const { getDidHashes } = await import("./pseudonymizer.js");
  try {
    getDidHashes("did:example:missing-pepper");
    assert.fail("Expected pseudonymizer_pepper_missing");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    assert.ok(message.includes("pseudonymizer_pepper_missing"));
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
