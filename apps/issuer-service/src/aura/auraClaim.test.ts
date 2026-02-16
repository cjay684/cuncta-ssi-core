import { strict as assert } from "node:assert";

const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);
import { SignJWT, exportJWK, generateKeyPair } from "jose";

process.env.NODE_ENV = "test";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.DEV_MODE = "true";
process.env.ISSUER_DID = "did:example:issuer";
process.env.SERVICE_JWT_SECRET = TEST_SECRET_HEX;
process.env.SERVICE_JWT_SECRET_ISSUER = process.env.SERVICE_JWT_SECRET;
process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";
process.env.SERVICE_JWT_AUDIENCE_ISSUER = "cuncta.service.issuer";
process.env.ISSUER_KEYS_BOOTSTRAP = "true";
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

const buildServiceToken = async () => {
  const key = new TextEncoder().encode(process.env.SERVICE_JWT_SECRET ?? "");
  return new SignJWT({ sub: "app-gateway", scope: "issuer:aura_claim" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuer("app-gateway")
    .setSubject("app-gateway")
    .setAudience(
      process.env.SERVICE_JWT_AUDIENCE_ISSUER ??
        process.env.SERVICE_JWT_AUDIENCE ??
        "cuncta-internal"
    )
    .setExpirationTime("5m")
    .sign(key);
};

const run = async () => {
  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "test-issuer";
  jwk.alg = "EdDSA";
  jwk.crv = "Ed25519";
  jwk.kty = "OKP";
  process.env.ISSUER_JWK = JSON.stringify(jwk);

  const { config } = await import("../config.js");
  config.SERVICE_JWT_SECRET_ISSUER = process.env.SERVICE_JWT_SECRET_ISSUER ?? "";
  config.SERVICE_JWT_AUDIENCE_ISSUER = process.env.SERVICE_JWT_AUDIENCE_ISSUER ?? "";
  config.ISSUER_KEYS_BOOTSTRAP = true;
  config.ISSUER_JWK = process.env.ISSUER_JWK ?? "";
  config.DEV_MODE = true;
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK ?? "";
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET ?? "";

  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { sha256Hex } = await import("../crypto/sha256.js");
  const { getDidHashes } = await import("../pseudonymizer.js");

  const app = buildServer();
  await app.ready();
  const db = await getDb();

  await db("aura_issuance_queue").del();
  await db("aura_state").del();
  await db("aura_signals").del();
  await db("aura_rules").where({ rule_id: "test.claim.rule.v1" }).del();
  await db("issuance_events").del();
  await db("privacy_restrictions").del();
  await db("privacy_tombstones").del();

  await db("credential_types")
    .insert({
      vct: "cuncta.marketplace.seller_good_standing",
      json_schema: JSON.stringify({
        type: "object",
        properties: {
          seller_good_standing: { type: "boolean" },
          domain: { type: "string" },
          as_of: { type: "string", format: "date-time" },
          tier: { type: "string", enum: ["bronze", "silver", "gold"] }
        },
        required: ["seller_good_standing", "domain", "as_of", "tier"],
        additionalProperties: false
      }),
      sd_defaults: JSON.stringify(["seller_good_standing", "domain", "as_of", "tier"]),
      display: JSON.stringify({
        title: "Seller Good Standing",
        claims: [
          { path: "tier", label: "Tier" },
          { path: "as_of", label: "As of" }
        ]
      }),
      purpose_limits: JSON.stringify({ actions: ["marketplace.list_item"] }),
      presentation_templates: JSON.stringify({
        required_disclosures: ["seller_good_standing", "tier"]
      }),
      revocation_config: JSON.stringify({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048
      }),
      catalog_hash: null,
      catalog_signature: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .onConflict("vct")
    .merge({
      json_schema: JSON.stringify({
        type: "object",
        properties: {
          seller_good_standing: { type: "boolean" },
          domain: { type: "string" },
          as_of: { type: "string", format: "date-time" },
          tier: { type: "string", enum: ["bronze", "silver", "gold"] }
        },
        required: ["seller_good_standing", "domain", "as_of", "tier"],
        additionalProperties: false
      }),
      sd_defaults: JSON.stringify(["seller_good_standing", "domain", "as_of", "tier"]),
      display: JSON.stringify({
        title: "Seller Good Standing",
        claims: [
          { path: "tier", label: "Tier" },
          { path: "as_of", label: "As of" }
        ]
      }),
      purpose_limits: JSON.stringify({ actions: ["marketplace.list_item"] }),
      presentation_templates: JSON.stringify({
        required_disclosures: ["seller_good_standing", "tier"]
      }),
      revocation_config: JSON.stringify({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048
      }),
      catalog_hash: null,
      catalog_signature: null,
      updated_at: new Date().toISOString()
    });

  await db("aura_rules").insert({
    rule_id: "test.claim.rule.v1",
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    rule_logic: JSON.stringify({
      window_seconds: 60,
      per_counterparty_cap: 3,
      per_counterparty_decay_exponent: 0.5,
      diversity_min: 1,
      collusion_cluster_threshold: 0.6,
      collusion_multiplier: 0.7,
      score: { min_silver: 1, min_gold: 2 },
      output: {
        claims: {
          seller_good_standing: true,
          domain: "{domain}",
          tier: "{tier}",
          as_of: "{now}"
        }
      }
    }),
    enabled: true,
    version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const token = await buildServiceToken();

  const noQueue = await app.inject({
    method: "POST",
    url: "/v1/aura/claim",
    headers: { authorization: `Bearer ${token}` },
    payload: {
      subjectDid: "did:example:holder",
      output_vct: "cuncta.marketplace.seller_good_standing"
    }
  });
  assert.equal(noQueue.statusCode, 404);

  const subjectDid = "did:example:holder";
  const subjectHash = getDidHashes(subjectDid).primary;
  await db("aura_state").insert({
    subject_did_hash: subjectHash,
    domain: "marketplace",
    state: JSON.stringify({ tier: "silver", score: 5, diversity: 3 }),
    updated_at: new Date().toISOString()
  });
  await db("aura_issuance_queue").insert({
    queue_id: "queue-1",
    rule_id: "test.claim.rule.v1",
    subject_did_hash: subjectHash,
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    reason_hash: sha256Hex("reason"),
    status: "PENDING",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const first = await app.inject({
    method: "POST",
    url: "/v1/aura/claim",
    headers: { authorization: `Bearer ${token}` },
    payload: { subjectDid, output_vct: "cuncta.marketplace.seller_good_standing" }
  });
  if (first.statusCode !== 200) {
    throw new Error(`aura_claim_failed:${first.statusCode}:${first.body}`);
  }
  const firstPayload = first.json();
  assert.equal(firstPayload.status, "ISSUED");

  const second = await app.inject({
    method: "POST",
    url: "/v1/aura/claim",
    headers: { authorization: `Bearer ${token}` },
    payload: { subjectDid, output_vct: "cuncta.marketplace.seller_good_standing" }
  });
  assert.equal(second.statusCode, 200);
  const secondPayload = second.json();
  assert.equal(secondPayload.status, "ALREADY_ISSUED");

  const issuanceCount = await db("issuance_events")
    .where({ vct: "cuncta.marketplace.seller_good_standing", subject_did_hash: subjectHash })
    .count<{ count: string }>("event_id as count")
    .first();
  assert.equal(Number(issuanceCount?.count ?? 0), 1);

  await db("aura_issuance_queue").insert({
    queue_id: "queue-2",
    rule_id: "test.claim.rule.v1",
    subject_did_hash: subjectHash,
    domain: "marketplace",
    output_vct: "cuncta.marketplace.seller_good_standing",
    reason_hash: sha256Hex("reason-2"),
    status: "PENDING",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const [c1, c2] = await Promise.all([
    app.inject({
      method: "POST",
      url: "/v1/aura/claim",
      headers: { authorization: `Bearer ${token}` },
      payload: { subjectDid, output_vct: "cuncta.marketplace.seller_good_standing" }
    }),
    app.inject({
      method: "POST",
      url: "/v1/aura/claim",
      headers: { authorization: `Bearer ${token}` },
      payload: { subjectDid, output_vct: "cuncta.marketplace.seller_good_standing" }
    })
  ]);
  assert.ok([c1.statusCode, c2.statusCode].includes(200));
  assert.ok([c1.statusCode, c2.statusCode].includes(409));

  const issuanceCountAfter = await db("issuance_events")
    .where({ vct: "cuncta.marketplace.seller_good_standing", subject_did_hash: subjectHash })
    .count<{ count: string }>("event_id as count")
    .first();
  assert.equal(Number(issuanceCountAfter?.count ?? 0), 2);

  await app.close();
};

run().catch((error) => {
  if (error instanceof Error) {
    console.error(error.stack ?? error.message);
  } else {
    console.error(error);
  }
  process.exit(1);
});
