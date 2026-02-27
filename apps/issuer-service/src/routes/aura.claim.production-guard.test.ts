import { test } from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "production";
process.env.DEV_MODE = "false";
process.env.ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? "http://issuer.test";
process.env.ISSUER_DID = process.env.ISSUER_DID ?? "did:example:issuer";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "issuer-test-pepper-123456";

test("/v1/aura/claim is rejected without service auth in production", async () => {
  const { buildServer } = await import("../server.js");
  const app = buildServer();
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/v1/aura/claim",
    payload: { subjectDid: "did:hedera:testnet:subject:1", output_vct: "cuncta.social.can_post" }
  });
  assert.ok(response.statusCode >= 401 && response.statusCode <= 403);
  await app.close();
});
