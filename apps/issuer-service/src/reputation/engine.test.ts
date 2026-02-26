import { strict as assert } from "node:assert";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair } from "jose";
import { recordEvent, recomputeReputation } from "./engine.js";

process.env.NODE_ENV = "test";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.ISSUER_DID = "did:example:issuer";
process.env.POLICY_SIGNING_JWK =
  process.env.POLICY_SIGNING_JWK ??
  JSON.stringify({
    crv: "Ed25519",
    kty: "OKP",
    x: "eizSDrSrl36htHi8iHaUO9Txf0nfp-JnQzSSdkuv4A0",
    d: "n6577z46eZat0Wv-el3Vg_LaJpVXo5ZYLZ_q5OMYpPk",
    kid: "policy-test"
  });
process.env.POLICY_SIGNING_BOOTSTRAP = "true";
process.env.ANCHOR_AUTH_SECRET =
  process.env.ANCHOR_AUTH_SECRET ?? "test-anchor-auth-secret-please-rotate";
process.env.ISSUER_KEYS_BOOTSTRAP = "true";

const run = async () => {
  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "test-issuer";
  jwk.alg = "EdDSA";
  jwk.crv = "Ed25519";
  jwk.kty = "OKP";
  process.env.ISSUER_JWK = JSON.stringify(jwk);

  const { config } = await import("../config.js");
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;
  config.ISSUER_KEYS_BOOTSTRAP = true;
  config.ISSUER_JWK = process.env.ISSUER_JWK;

  const actorDid = `did:example:actor:${randomUUID()}`;
  const now = new Date().toISOString();

  for (let i = 0; i < 10; i += 1) {
    await recordEvent({
      actor_pseudonym: actorDid,
      counterparty_pseudonym: "did:example:counterparty:repeat",
      domain: "marketplace",
      event_type: "marketplace.listing_success",
      timestamp: now
    });
  }

  const lowTier = await recomputeReputation(actorDid);
  const lowDomain = lowTier.domains.find((entry) => entry.domain === "marketplace");
  const lowState =
    typeof lowDomain?.state === "string"
      ? (JSON.parse(lowDomain.state) as Record<string, unknown>)
      : (lowDomain?.state as Record<string, unknown> | undefined);
  assert.equal(lowState?.tier, "bronze");

  for (let i = 0; i < 12; i += 1) {
    await recordEvent({
      actor_pseudonym: actorDid,
      counterparty_pseudonym: `did:example:counterparty:${i}`,
      domain: "marketplace",
      event_type: "marketplace.listing_success",
      timestamp: now
    });
  }

  const highTier = await recomputeReputation(actorDid);
  const highDomain = highTier.domains.find((entry) => entry.domain === "marketplace");
  const highState =
    typeof highDomain?.state === "string"
      ? (JSON.parse(highDomain.state) as Record<string, unknown>)
      : (highDomain?.state as Record<string, unknown> | undefined);
  assert.ok(["silver", "gold"].includes(String(highState?.tier)));
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
