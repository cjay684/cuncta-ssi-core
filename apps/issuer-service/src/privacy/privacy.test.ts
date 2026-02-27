import { strict as assert } from "node:assert";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { sha256Hex } from "../crypto/sha256.js";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.PRIVACY_CHALLENGE_TTL_SECONDS = "60";
process.env.PRIVACY_TOKEN_TTL_SECONDS = "900";
process.env.PSEUDONYMIZER_PEPPER = "test-pepper";
process.env.PSEUDONYMIZER_ALLOW_LEGACY = "true";
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

const run = async () => {
  const { config } = await import("../config.js");
  config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
  config.POLICY_SIGNING_BOOTSTRAP = true;
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;
  const { buildServer } = await import("../server.js");
  const { getDb } = await import("../db.js");
  const { processAuraSignalsOnce } = await import("../aura/auraWorker.js");
  const { getDidHashes } = await import("../pseudonymizer.js");

  const app = buildServer();
  await app.ready();
  const db = await getDb();

  await db("privacy_requests").del();
  await db("privacy_tokens").del();
  await db("privacy_restrictions").del();
  await db("privacy_tombstones").del();
  await db("aura_state").del();
  await db("aura_signals").del();
  await db("aura_issuance_queue").del();
  await db("aura_rules").update({ enabled: false });
  await db("obligation_events").del();
  await db("obligations_executions").del();
  await db("rate_limit_events").del();
  await db("command_center_audit_events").del();
  await db("issuance_events").del();
  await db("status_lists").where({ status_list_id: "dsr_test" }).del();

  const did = "did:hedera:testnet:dsr:holder";
  const hashes = getDidHashes(did);
  const didHash = hashes.primary;
  const legacyHash = hashes.legacy as string;

  await db("status_lists").insert({
    status_list_id: "dsr_test",
    purpose: "revocation",
    bitstring_size: 2048,
    current_version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  await db("issuance_events").insert({
    event_id: "evt_dsr_1",
    vct: "cuncta.marketplace.seller_good_standing",
    subject_did_hash: legacyHash,
    credential_fingerprint: sha256Hex("cred_fingerprint"),
    status_list_id: "dsr_test",
    status_index: 1,
    issued_at: new Date().toISOString()
  });

  await db("aura_state").insert({
    subject_did_hash: legacyHash,
    domain: "marketplace",
    state: JSON.stringify({
      score: 2,
      diversity: 1,
      tier: "bronze",
      window_days: 30,
      last_signal_at: new Date().toISOString()
    }),
    updated_at: new Date().toISOString()
  });

  await db("aura_signals").insert({
    subject_did_hash: legacyHash,
    domain: "marketplace",
    signal: "marketplace.listing_success",
    weight: 1,
    event_hash: sha256Hex("signal_dsr_1"),
    created_at: new Date().toISOString()
  });

  await db("obligation_events").insert({
    action_id: "marketplace.list_item",
    event_type: "VERIFY",
    subject_did_hash: legacyHash,
    token_hash: sha256Hex("token_dsr_1"),
    challenge_hash: sha256Hex("challenge_dsr_1"),
    event_hash: sha256Hex("event_dsr_1"),
    created_at: new Date().toISOString()
  });

  await db("obligations_executions").insert({
    id: "obl_dsr_1",
    action_id: "marketplace.list_item",
    policy_id: "marketplace.list_item.v1",
    policy_version: 1,
    decision: "ALLOW",
    subject_did_hash: legacyHash,
    token_hash: sha256Hex("token_dsr_1"),
    challenge_hash: sha256Hex("challenge_dsr_1"),
    obligations_hash: sha256Hex("obl_hash"),
    executed_at: new Date().toISOString(),
    anchor_payload_hash: sha256Hex("anchor_payload"),
    status: "CONFIRMED"
  });

  await db("rate_limit_events").insert({
    subject_hash: legacyHash,
    action_id: "aura.claim",
    created_at: new Date().toISOString()
  });
  await db("command_center_audit_events").insert([
    {
      id: "11111111-1111-4111-8111-111111111111",
      created_at: new Date().toISOString(),
      subject_hash: didHash,
      event_type: "command_plan_requested",
      payload_json: {}
    },
    {
      id: "22222222-2222-4222-8222-222222222222",
      created_at: new Date().toISOString(),
      subject_hash: legacyHash,
      event_type: "command_plan_requested",
      payload_json: {}
    },
    {
      id: "33333333-3333-4333-8333-333333333333",
      created_at: new Date().toISOString(),
      subject_hash: "unrelated_subject_hash",
      event_type: "command_plan_requested",
      payload_json: {}
    }
  ]);

  const requestResponse = await app.inject({
    method: "POST",
    url: "/v1/privacy/request",
    payload: { did }
  });
  assert.equal(requestResponse.statusCode, 200);
  const requestPayload = requestResponse.json() as {
    requestId: string;
    nonce: string;
    audience: string;
  };
  assert.ok(requestPayload.requestId);
  assert.ok(requestPayload.nonce);
  assert.ok(requestPayload.audience);

  const holderKeys = await generateKeyPair("EdDSA", { extractable: true });
  const holderPublicJwk = await exportJWK(holderKeys.publicKey);
  holderPublicJwk.kid = "holder";
  holderPublicJwk.alg = "EdDSA";
  holderPublicJwk.crv = "Ed25519";
  holderPublicJwk.kty = "OKP";
  const nowSeconds = Math.floor(Date.now() / 1000);
  const kbJwt = await new SignJWT({
    aud: requestPayload.audience,
    nonce: requestPayload.nonce,
    iat: nowSeconds,
    exp: nowSeconds + 120,
    cnf: { jwk: { kty: "OKP", crv: "Ed25519", x: holderPublicJwk.x, alg: "EdDSA" } }
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .sign(holderKeys.privateKey);

  const confirmResponse = await app.inject({
    method: "POST",
    url: "/v1/privacy/confirm",
    payload: {
      requestId: requestPayload.requestId,
      nonce: requestPayload.nonce,
      kbJwt
    }
  });
  assert.equal(confirmResponse.statusCode, 200);
  const confirmPayload = confirmResponse.json() as { dsrToken: string };
  assert.ok(confirmPayload.dsrToken);
  let activeToken = confirmPayload.dsrToken;

  const exportResponse = await app.inject({
    method: "GET",
    url: "/v1/privacy/export",
    headers: { authorization: `Bearer ${activeToken}` }
  });
  assert.equal(exportResponse.statusCode, 200);
  const exportPayload = exportResponse.json() as { nextToken?: string; issuance?: unknown[] };
  const exportText = JSON.stringify(exportPayload);
  assert.ok(!exportText.includes("did:"), "export must not include raw DIDs");
  assert.ok(!exportText.includes("eyJ"), "export must not include JWTs");
  assert.ok(!exportText.includes("~"), "export must not include SD-JWT presentations");
  assert.ok(exportPayload.nextToken, "export should return next token");
  assert.ok((exportPayload.issuance ?? []).length > 0, "export should include legacy issuance");

  const reuseResponse = await app.inject({
    method: "GET",
    url: "/v1/privacy/export",
    headers: { authorization: `Bearer ${activeToken}` }
  });
  assert.equal(reuseResponse.statusCode, 401);
  activeToken = exportPayload.nextToken as string;

  const explainResponse = await app.inject({
    method: "GET",
    url: "/v1/aura/explain",
    headers: { authorization: `Bearer ${activeToken}` }
  });
  assert.equal(explainResponse.statusCode, 200);

  const restrictResponse = await app.inject({
    method: "POST",
    url: "/v1/privacy/restrict",
    headers: { authorization: `Bearer ${activeToken}` },
    payload: { reason: "user request" }
  });
  assert.equal(restrictResponse.statusCode, 200);
  const restrictPayload = restrictResponse.json() as { nextToken?: string };
  assert.ok(restrictPayload.nextToken, "restrict should return next token");
  activeToken = restrictPayload.nextToken as string;
  const restrictAuditPrimary = await db("command_center_audit_events")
    .where({ subject_hash: didHash })
    .first();
  const restrictAuditLegacy = await db("command_center_audit_events")
    .where({ subject_hash: legacyHash })
    .first();
  assert.ok(restrictAuditPrimary, "restrict should not delete command audit rows");
  assert.ok(restrictAuditLegacy, "restrict should not delete legacy command audit rows");

  const eraseResponse = await app.inject({
    method: "POST",
    url: "/v1/privacy/erase",
    headers: { authorization: `Bearer ${activeToken}` },
    payload: { mode: "unlink" }
  });
  assert.equal(eraseResponse.statusCode, 200);

  const tombstonePrimary = await db("privacy_tombstones").where({ did_hash: didHash }).first();
  const tombstoneLegacy = await db("privacy_tombstones").where({ did_hash: legacyHash }).first();
  assert.ok(tombstonePrimary, "tombstone should exist for primary hash");
  assert.ok(tombstoneLegacy, "tombstone should exist for legacy hash");
  const stateRow = await db("aura_state").where({ subject_did_hash: didHash }).first();
  assert.equal(stateRow, undefined);
  const signalRow = await db("aura_signals").where({ subject_did_hash: didHash }).first();
  assert.equal(signalRow, undefined);
  const issuanceRow = await db("issuance_events").where({ event_id: "evt_dsr_1" }).first();
  assert.equal(issuanceRow?.subject_did_hash ?? null, null);
  const auditPrimary = await db("command_center_audit_events")
    .where({ subject_hash: didHash })
    .first();
  const auditLegacy = await db("command_center_audit_events")
    .where({ subject_hash: legacyHash })
    .first();
  const auditUnrelated = await db("command_center_audit_events")
    .where({ subject_hash: "unrelated_subject_hash" })
    .first();
  assert.equal(auditPrimary, undefined);
  assert.equal(auditLegacy, undefined);
  assert.ok(auditUnrelated, "erase should not delete unrelated command audit rows");

  await db("aura_signals").insert({
    subject_did_hash: didHash,
    domain: "marketplace",
    signal: "marketplace.listing_success",
    weight: 1,
    event_hash: sha256Hex("signal_dsr_after_erase"),
    created_at: new Date().toISOString()
  });
  await processAuraSignalsOnce();
  const stateAfter = await db("aura_state").where({ subject_did_hash: didHash }).first();
  assert.equal(stateAfter, undefined);

  await app.close();
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
