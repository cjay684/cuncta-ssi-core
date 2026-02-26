import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.HEDERA_NETWORK = "testnet";
process.env.DID_SERVICE_BASE_URL = "http://localhost:3001";
process.env.ISSUER_SERVICE_BASE_URL = "http://localhost:3002";
process.env.VERIFIER_SERVICE_BASE_URL = "http://localhost:3003";
process.env.POLICY_SERVICE_BASE_URL = "http://localhost:3004";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.SERVICE_JWT_SECRET = "test-secret-12345678901234567890123456789012";
process.env.SERVICE_JWT_SECRET_ISSUER = "test-secret-12345678901234567890123456789012-issuer";
process.env.ALLOW_LEGACY_SERVICE_JWT_SECRET = "false";
process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";
process.env.PSEUDONYMIZER_PEPPER = "pepper-test-123456";
process.env.USER_PAYS_HANDOFF_SECRET =
  process.env.USER_PAYS_HANDOFF_SECRET ?? "user-pays-handoff-secret-12345678901234567890";

const run = async (name: string, fn: () => Promise<void>) => {
  try {
    await fn();
    // eslint-disable-next-line no-console
    console.log(`ok - ${name}`);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(`not ok - ${name}`);
    // eslint-disable-next-line no-console
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

await run("oid4vci aura offer rejects invalid domain scope", async () => {
  const { buildServer } = await import("../server.js");
  const { config } = await import("../config.js");
  let upstreamCalled = false;
  const app = buildServer({
    configOverride: { ...config },
    fetchImpl: async () => {
      upstreamCalled = true;
      throw new Error("upstream should not be called");
    }
  });
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/oid4vci/aura/offer",
    payload: {
      credential_configuration_id: "aura:cuncta.social.trusted_creator",
      domain: "social:missing",
      subjectDid: "did:hedera:testnet:subject:1",
      offer_nonce: "nonce-1234567890",
      proof_jwt: "proofjwt-1234567890"
    }
  });
  assert.equal(response.statusCode, 400);
  assert.equal(upstreamCalled, false);
  await app.close();
});

await run("oid4vci aura offer requires matching space_id scope", async () => {
  const { buildServer } = await import("../server.js");
  const { config } = await import("../config.js");
  let upstreamCalled = false;
  const app = buildServer({
    configOverride: { ...config },
    fetchImpl: async () => {
      upstreamCalled = true;
      throw new Error("upstream should not be called");
    }
  });
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/oid4vci/aura/offer",
    payload: {
      credential_configuration_id: "aura:cuncta.social.space.moderator",
      domain: "space:11111111-1111-1111-1111-111111111111",
      // Must be a syntactically valid UUID; mismatch is tested against `domain`.
      space_id: "22222222-2222-2222-8222-222222222222",
      subjectDid: "did:hedera:testnet:subject:1",
      offer_nonce: "nonce-1234567890",
      proof_jwt: "proofjwt-1234567890"
    }
  });
  assert.equal(response.statusCode, 400);
  assert.equal(upstreamCalled, false);
  await app.close();
});

await run("oid4vci aura offer forwards when scope is valid", async () => {
  const { buildServer } = await import("../server.js");
  const { config } = await import("../config.js");
  let upstreamCalled = false;
  const app = buildServer({
    configOverride: { ...config },
    fetchImpl: async (url, init) => {
      upstreamCalled = true;
      assert.ok(String(url).includes("/v1/internal/oid4vci/preauth/aura"));
      assert.equal(init?.method, "POST");
      return new Response(
        JSON.stringify({
          credential_offer: {
            credential_issuer: "http://localhost:3002",
            credential_configuration_ids: ["aura:cuncta.social.trusted_creator"],
            grants: {
              "urn:ietf:params:oauth:grant-type:pre-authorized_code": { "pre-authorized_code": "code" }
            }
          },
          expires_at: new Date(Date.now() + 60_000).toISOString()
        }),
        { status: 200, headers: { "content-type": "application/json" } }
      );
    }
  });
  await app.ready();
  const response = await app.inject({
    method: "POST",
    url: "/oid4vci/aura/offer",
    payload: {
      credential_configuration_id: "aura:cuncta.social.trusted_creator",
      domain: "social",
      subjectDid: "did:hedera:testnet:subject:1",
      offer_nonce: "nonce-1234567890",
      proof_jwt: "proofjwt-1234567890"
    }
  });
  assert.equal(response.statusCode, 200);
  assert.equal(upstreamCalled, true);
  await app.close();
});

