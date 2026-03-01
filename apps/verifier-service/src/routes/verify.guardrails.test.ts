import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import fastify from "fastify";
import { createDb, runMigrations } from "@cuncta/db";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from "jose";
import { hashCanonicalJson } from "@cuncta/shared";
import { issueSdJwtVc } from "@cuncta/sdjwt";
import { sha256Base64Url } from "../crypto/sha256.js";
import { metrics } from "../metrics.js";

const dbUrl = process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

const nowIso = () => new Date().toISOString();
const makeNonce = () => `nonce-${randomUUID()}-1234567890`;
const makeAction = () => `identity.verify.${randomUUID()}`;

const seedPolicy = async (input: {
  db: ReturnType<typeof createDb>;
  actionId: string;
  policyId: string;
  version: number;
  logic: Record<string, unknown>;
  policyJwk: JWK;
}) => {
  const policyHash = hashCanonicalJson({
    policy_id: input.policyId,
    action_id: input.actionId,
    version: input.version,
    enabled: true,
    logic: input.logic
  });
  const signingKey = await importJWK(input.policyJwk, "EdDSA");
  const signature = await new SignJWT({ hash: policyHash })
    .setProtectedHeader({
      alg: "EdDSA",
      typ: "policy-hash+jwt",
      kid: input.policyJwk.kid
    })
    .setIssuedAt()
    .sign(signingKey);
  await input.db("policies").insert({
    policy_id: input.policyId,
    action_id: input.actionId,
    version: input.version,
    enabled: true,
    logic: input.logic,
    policy_hash: policyHash,
    policy_signature: signature,
    created_at: nowIso(),
    updated_at: nowIso()
  });
  return policyHash;
};

const seedChallenge = async (input: {
  db: ReturnType<typeof createDb>;
  actionId: string;
  policyId: string;
  policyVersion: number;
  policyHash: string;
  nonce: string;
  audience: string;
}) => {
  await input.db("verification_challenges").insert({
    challenge_id: randomUUID(),
    challenge_hash: createHash("sha256").update(input.nonce).digest("hex"),
    action_id: input.actionId,
    policy_id: input.policyId,
    policy_version: input.policyVersion,
    policy_hash: input.policyHash,
    audience: input.audience,
    expires_at: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    created_at: nowIso()
  });
};

const createPresentation = async (input: {
  issuerJwk: JWK;
  holderPublicJwk: JWK;
  holderPrivateJwk: JWK;
  subjectDid: string;
  issuerDid: string;
  vct: string;
  nonce: string;
  audience: string;
  claims?: Record<string, unknown>;
  selectiveDisclosure?: string[];
}) => {
  const sdJwt = await issueSdJwtVc({
    issuerJwk: input.issuerJwk,
    payload: {
      iss: input.issuerDid,
      sub: input.subjectDid,
      vct: input.vct,
      ...(input.claims ?? {}),
      status: {
        statusListCredential: "/status-lists/default",
        statusListIndex: "0"
      }
    },
    selectiveDisclosure: input.selectiveDisclosure ?? [],
    typMode: "strict"
  });
  const kbKey = await importJWK(input.holderPrivateJwk, "EdDSA");
  const kbJwt = await new SignJWT({
    aud: input.audience,
    nonce: input.nonce,
    sd_hash: sha256Base64Url(sdJwt),
    cnf: {
      jwk: input.holderPublicJwk
    }
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(kbKey);
  return `${sdJwt}${kbJwt}`;
};

test("policy floor denies pinned downgraded policy versions deterministically", async () => {
  process.env.NODE_ENV = "development";
  process.env.POLICY_VERSION_FLOOR_ENFORCED = "true";
  process.env.VERIFY_MAX_PRESENTATION_BYTES = "65536";
  process.env.ISSUER_SERVICE_BASE_URL = "http://127.0.0.1:1";
  process.env.POLICY_SERVICE_BASE_URL = "http://127.0.0.1:1";

  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const policyJwk = await exportJWK(privateKey);
  policyJwk.kid = `policy-kid-${randomUUID()}`;
  process.env.POLICY_SIGNING_JWK = JSON.stringify(policyJwk);

  const db = createDb(dbUrl);
  try {
    await runMigrations(db);
    const actionId = makeAction();
    const audience = `origin:https://verifier.cuncta.test/${actionId}`;
    const nonce = makeNonce();

    await db("verification_challenges").del();
    await db("policy_version_floor").where({ action_id: actionId }).del();
    await db("policies").where({ action_id: actionId }).del();
    await db("actions").where({ action_id: actionId }).del();

    await db("actions").insert({
      action_id: actionId,
      description: "deterministic floor test",
      created_at: nowIso(),
      updated_at: nowIso()
    });

    const policyIdV1 = `policy.floor.${randomUUID()}.v1`;
    const policyHashV1 = await seedPolicy({
      db,
      actionId,
      policyId: policyIdV1,
      version: 1,
      logic: { requirements: [], obligations: [] },
      policyJwk
    });

    await db("policy_version_floor").insert({
      action_id: actionId,
      min_version: 2,
      updated_at: nowIso()
    });

    await seedChallenge({
      db,
      actionId,
      policyId: policyIdV1,
      policyVersion: 1,
      policyHash: policyHashV1,
      nonce,
      audience
    });

    const { config } = await import("../config.js");
    config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
    config.POLICY_VERSION_FLOOR_ENFORCED = true;
    config.VERIFY_MAX_PRESENTATION_BYTES = 65536;
    config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
    config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://127.0.0.1:1";

    const { registerVerifyRoutes, __test__ } = await import("./verify.js");
    __test__.resetIssuerKeyCache();
    __test__.resetPolicyVerifyKey();
    const app = fastify();
    registerVerifyRoutes(app);
    const response = await app.inject({
      method: "POST",
      url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
      payload: {
        presentation: "xxxxxxxxxx",
        nonce,
        audience
      }
    });
    assert.equal(response.statusCode, 200);
    const body = response.json() as { decision?: string; reasons?: string[] };
    assert.equal(body.decision, "DENY");
    assert.ok(body.reasons?.includes("policy_version_downgrade"));
    await app.close();
  } finally {
    await db.destroy();
  }
});

test("jwks refresh-on-kid-miss succeeds and records miss/refresh metrics", async () => {
  process.env.NODE_ENV = "development";
  process.env.POLICY_VERSION_FLOOR_ENFORCED = "true";
  process.env.VERIFY_MAX_PRESENTATION_BYTES = "65536";

  const jwksServer = fastify();
  const { privateKey: stalePriv, publicKey: stalePub } = await generateKeyPair("EdDSA", {
    extractable: true
  });
  void stalePriv;
  const staleJwk = await exportJWK(stalePub);
  staleJwk.kid = `stale-${randomUUID()}`;
  staleJwk.alg = "EdDSA";

  const { privateKey: issuerPriv, publicKey: issuerPub } = await generateKeyPair("EdDSA", {
    extractable: true
  });
  const issuerPrivateJwk = await exportJWK(issuerPriv);
  issuerPrivateJwk.kid = `issuer-${randomUUID()}`;
  issuerPrivateJwk.alg = "EdDSA";
  const issuerPublicJwk = await exportJWK(issuerPub);
  issuerPublicJwk.kid = issuerPrivateJwk.kid;
  issuerPublicJwk.alg = "EdDSA";

  let jwksCalls = 0;
  jwksServer.get("/jwks.json", async () => {
    jwksCalls += 1;
    if (jwksCalls === 1) {
      return { keys: [staleJwk] };
    }
    return { keys: [staleJwk, issuerPublicJwk] };
  });
  const jwksAddress = await jwksServer.listen({ port: 0, host: "127.0.0.1" });

  const { privateKey: policyPriv } = await generateKeyPair("EdDSA", { extractable: true });
  const policyJwk = await exportJWK(policyPriv);
  policyJwk.kid = `policy-kid-${randomUUID()}`;
  process.env.POLICY_SIGNING_JWK = JSON.stringify(policyJwk);
  process.env.ISSUER_SERVICE_BASE_URL = jwksAddress;
  process.env.POLICY_SERVICE_BASE_URL = "http://127.0.0.1:1";

  const db = createDb(dbUrl);
  try {
    await runMigrations(db);
    const actionId = makeAction();
    const audience = `origin:https://verifier.cuncta.test/${actionId}`;
    const nonce = makeNonce();
    const issuerDid = `did:hedera:testnet:${randomUUID()}`;
    const subjectDid = `did:hedera:testnet:${randomUUID()}`;
    const vct = `cuncta.age_over_18.${randomUUID()}`;

    await db("verification_challenges").del();
    await db("policy_version_floor").where({ action_id: actionId }).del();
    await db("policies").where({ action_id: actionId }).del();
    await db("actions").where({ action_id: actionId }).del();

    await db("actions").insert({
      action_id: actionId,
      description: "deterministic jwks refresh test",
      created_at: nowIso(),
      updated_at: nowIso()
    });

    const policyId = `policy.jwks.${randomUUID()}.v2`;
    const policyHash = await seedPolicy({
      db,
      actionId,
      policyId,
      version: 2,
      logic: {
        requirements: [
          {
            vct,
            issuer: { mode: "allowlist", allowed: [issuerDid] },
            disclosures: [],
            predicates: [],
            revocation: { required: false }
          }
        ],
        obligations: []
      },
      policyJwk
    });
    await db("policy_version_floor")
      .insert({
        action_id: actionId,
        min_version: 2,
        updated_at: nowIso()
      })
      .onConflict("action_id")
      .merge({ min_version: 2, updated_at: nowIso() });

    await seedChallenge({
      db,
      actionId,
      policyId,
      policyVersion: 2,
      policyHash,
      nonce,
      audience
    });

    const { privateKey: holderPriv, publicKey: holderPub } = await generateKeyPair("EdDSA", {
      extractable: true
    });
    const holderPrivateJwk = await exportJWK(holderPriv);
    holderPrivateJwk.alg = "EdDSA";
    const holderPublicJwk = await exportJWK(holderPub);
    holderPublicJwk.alg = "EdDSA";
    const presentation = await createPresentation({
      issuerJwk: issuerPrivateJwk,
      holderPublicJwk,
      holderPrivateJwk,
      subjectDid,
      issuerDid,
      vct,
      nonce,
      audience
    });

    const { config } = await import("../config.js");
    config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
    config.POLICY_VERSION_FLOOR_ENFORCED = true;
    config.ISSUER_SERVICE_BASE_URL = jwksAddress;
    config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
    config.ISSUER_JWKS = undefined;

    const { registerVerifyRoutes, __test__ } = await import("./verify.js");
    __test__.resetIssuerKeyCache();
    __test__.resetPolicyVerifyKey();
    const app = fastify();
    registerVerifyRoutes(app);
    const metricsBefore = metrics.render();
    const verifyResponse = await app.inject({
      method: "POST",
      url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
      payload: {
        presentation,
        nonce,
        audience
      }
    });
    assert.equal(verifyResponse.statusCode, 200);
    const verifyBody = verifyResponse.json() as { decision?: string; reasons?: string[] };
    // #region agent log
    fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
      body: JSON.stringify({
        sessionId: "6783de",
        runId: "guardrails-pre-fix",
        hypothesisId: "H1",
        location: "verify.guardrails.test.ts:353",
        message: "jwks refresh test verify response",
        data: {
          statusCode: verifyResponse.statusCode,
          decision: verifyBody.decision,
          reasons: verifyBody.reasons ?? []
        },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
    assert.equal(verifyBody.decision, "ALLOW");
    assert.equal(jwksCalls >= 2, true);

    const metricsText = metrics.render();
    assert.notEqual(metricsText, metricsBefore);
    assert.match(metricsText, /jwks_kid_miss_total\{service="verifier-service"\} [1-9]\d*/);
    assert.match(
      metricsText,
      /jwks_cache_refresh_total\{reason="kid_miss",service="verifier-service"\} [1-9]\d*/
    );
    await app.close();
  } finally {
    await db.destroy();
    await jwksServer.close();
  }
});

test("jwks kid miss denies when refresh still lacks key", async () => {
  process.env.NODE_ENV = "development";
  process.env.POLICY_VERSION_FLOOR_ENFORCED = "true";
  process.env.VERIFY_MAX_PRESENTATION_BYTES = "65536";

  const jwksServer = fastify();
  const { publicKey: stalePub } = await generateKeyPair("EdDSA", { extractable: true });
  const staleJwk = await exportJWK(stalePub);
  staleJwk.kid = `stale-${randomUUID()}`;
  staleJwk.alg = "EdDSA";
  jwksServer.get("/jwks.json", async () => ({ keys: [staleJwk] }));
  const jwksAddress = await jwksServer.listen({ port: 0, host: "127.0.0.1" });

  const { privateKey: policyPriv } = await generateKeyPair("EdDSA", { extractable: true });
  const policyJwk = await exportJWK(policyPriv);
  policyJwk.kid = `policy-kid-${randomUUID()}`;
  process.env.POLICY_SIGNING_JWK = JSON.stringify(policyJwk);
  process.env.ISSUER_SERVICE_BASE_URL = jwksAddress;
  process.env.POLICY_SERVICE_BASE_URL = "http://127.0.0.1:1";

  const { privateKey: issuerPriv, publicKey: issuerPub } = await generateKeyPair("EdDSA", {
    extractable: true
  });
  const issuerPrivateJwk = await exportJWK(issuerPriv);
  issuerPrivateJwk.kid = `issuer-${randomUUID()}`;
  issuerPrivateJwk.alg = "EdDSA";
  const issuerPublicJwk = await exportJWK(issuerPub);
  issuerPublicJwk.kid = issuerPrivateJwk.kid;
  issuerPublicJwk.alg = "EdDSA";

  const db = createDb(dbUrl);
  try {
    await runMigrations(db);
    const actionId = makeAction();
    const audience = `origin:https://verifier.cuncta.test/${actionId}`;
    const nonce = makeNonce();
    const issuerDid = `did:hedera:testnet:${randomUUID()}`;
    const subjectDid = `did:hedera:testnet:${randomUUID()}`;
    const vct = `cuncta.age_over_18.${randomUUID()}`;

    await db("verification_challenges").del();
    await db("policy_version_floor").where({ action_id: actionId }).del();
    await db("policies").where({ action_id: actionId }).del();
    await db("actions").where({ action_id: actionId }).del();

    await db("actions").insert({
      action_id: actionId,
      description: "deterministic jwks miss deny test",
      created_at: nowIso(),
      updated_at: nowIso()
    });
    const policyId = `policy.jwks.miss.${randomUUID()}.v2`;
    const policyHash = await seedPolicy({
      db,
      actionId,
      policyId,
      version: 2,
      logic: {
        requirements: [
          {
            vct,
            issuer: { mode: "allowlist", allowed: [issuerDid] },
            disclosures: [],
            predicates: [],
            revocation: { required: false }
          }
        ],
        obligations: []
      },
      policyJwk
    });
    await db("policy_version_floor")
      .insert({
        action_id: actionId,
        min_version: 2,
        updated_at: nowIso()
      })
      .onConflict("action_id")
      .merge({ min_version: 2, updated_at: nowIso() });
    await seedChallenge({
      db,
      actionId,
      policyId,
      policyVersion: 2,
      policyHash,
      nonce,
      audience
    });

    const { privateKey: holderPriv, publicKey: holderPub } = await generateKeyPair("EdDSA", {
      extractable: true
    });
    const holderPrivateJwk = await exportJWK(holderPriv);
    holderPrivateJwk.alg = "EdDSA";
    const holderPublicJwk = await exportJWK(holderPub);
    holderPublicJwk.alg = "EdDSA";
    const presentation = await createPresentation({
      issuerJwk: issuerPrivateJwk,
      holderPublicJwk,
      holderPrivateJwk,
      subjectDid,
      issuerDid,
      vct,
      nonce,
      audience
    });

    const { config } = await import("../config.js");
    config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
    config.POLICY_VERSION_FLOOR_ENFORCED = true;
    config.ISSUER_SERVICE_BASE_URL = jwksAddress;
    config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
    config.ISSUER_JWKS = undefined;

    const { registerVerifyRoutes, __test__ } = await import("./verify.js");
    __test__.resetIssuerKeyCache();
    __test__.resetPolicyVerifyKey();
    const app = fastify();
    registerVerifyRoutes(app);
    const verifyResponse = await app.inject({
      method: "POST",
      url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
      payload: {
        presentation,
        nonce,
        audience
      }
    });
    assert.equal(verifyResponse.statusCode, 200);
    const verifyBody = verifyResponse.json() as { decision?: string; reasons?: string[] };
    // #region agent log
    fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
      body: JSON.stringify({
        sessionId: "6783de",
        runId: "guardrails-pre-fix",
        hypothesisId: "H2",
        location: "verify.guardrails.test.ts:435",
        message: "jwks miss deny-path response",
        data: {
          statusCode: verifyResponse.statusCode,
          decision: verifyBody.decision,
          reasons: verifyBody.reasons ?? []
        },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
    assert.equal(verifyBody.decision, "DENY");
    assert.ok(verifyBody.reasons?.includes("jwks_kid_not_found"));
    await app.close();
    void issuerPublicJwk;
  } finally {
    await db.destroy();
    await jwksServer.close();
  }
});

test("verifier denies space-scoped credential reuse across spaces", async () => {
  process.env.NODE_ENV = "development";
  process.env.POLICY_VERSION_FLOOR_ENFORCED = "true";
  process.env.VERIFY_MAX_PRESENTATION_BYTES = "65536";
  process.env.ISSUER_SERVICE_BASE_URL = "http://127.0.0.1:1";
  process.env.POLICY_SERVICE_BASE_URL = "http://127.0.0.1:1";

  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const policyJwk = await exportJWK(privateKey);
  policyJwk.kid = `policy-kid-${randomUUID()}`;
  process.env.POLICY_SIGNING_JWK = JSON.stringify(policyJwk);

  const { privateKey: issuerPriv, publicKey: issuerPub } = await generateKeyPair("EdDSA", {
    extractable: true
  });
  const issuerPrivateJwk = await exportJWK(issuerPriv);
  issuerPrivateJwk.kid = `issuer-${randomUUID()}`;
  issuerPrivateJwk.alg = "EdDSA";
  const issuerPublicJwk = await exportJWK(issuerPub);
  issuerPublicJwk.kid = issuerPrivateJwk.kid;
  issuerPublicJwk.alg = "EdDSA";

  const db = createDb(dbUrl);
  try {
    await runMigrations(db);
    const actionId = `space.post.create.${randomUUID()}`;
    const audience = `origin:https://verifier.cuncta.test/${actionId}`;
    const nonce = makeNonce();
    const spaceA = randomUUID();
    const spaceB = randomUUID();
    const issuerDid = `did:hedera:testnet:${randomUUID()}`;
    const subjectDid = `did:hedera:testnet:${randomUUID()}`;
    const vct = `cuncta.space.poster.${randomUUID()}`;

    await db("verification_challenges").del();
    await db("policy_version_floor").where({ action_id: actionId }).del();
    await db("policies").where({ action_id: actionId }).del();
    await db("actions").where({ action_id: actionId }).del();

    await db("actions").insert({
      action_id: actionId,
      description: "space context binding test",
      created_at: nowIso(),
      updated_at: nowIso()
    });

    const policyId = `policy.space.ctx.${randomUUID()}.v2`;
    const policyHash = await seedPolicy({
      db,
      actionId,
      policyId,
      version: 2,
      logic: {
        requirements: [
          {
            vct,
            issuer: { mode: "allowlist", allowed: [issuerDid] },
            disclosures: ["space_id"],
            predicates: [{ path: "poster", op: "eq", value: true }],
            context_predicates: [{ left: "context.space_id", right: "claims.space_id", op: "eq" }],
            revocation: { required: false }
          }
        ],
        obligations: []
      },
      policyJwk
    });

    await db("policy_version_floor")
      .insert({
        action_id: actionId,
        min_version: 2,
        updated_at: nowIso()
      })
      .onConflict("action_id")
      .merge({ min_version: 2, updated_at: nowIso() });

    await seedChallenge({
      db,
      actionId,
      policyId,
      policyVersion: 2,
      policyHash,
      nonce,
      audience
    });

    const { privateKey: holderPriv, publicKey: holderPub } = await generateKeyPair("EdDSA", {
      extractable: true
    });
    const holderPrivateJwk = await exportJWK(holderPriv);
    holderPrivateJwk.alg = "EdDSA";
    const holderPublicJwk = await exportJWK(holderPub);
    holderPublicJwk.alg = "EdDSA";

    const presentation = await createPresentation({
      issuerJwk: issuerPrivateJwk,
      holderPublicJwk,
      holderPrivateJwk,
      subjectDid,
      issuerDid,
      vct,
      nonce,
      audience,
      claims: {
        poster: true,
        space_id: spaceA
      },
      selectiveDisclosure: ["space_id"]
    });

    const { config } = await import("../config.js");
    config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
    config.POLICY_VERSION_FLOOR_ENFORCED = true;
    config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
    config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
    config.ISSUER_JWKS = JSON.stringify({ keys: [issuerPublicJwk] });

    const { registerVerifyRoutes, __test__ } = await import("./verify.js");
    __test__.resetIssuerKeyCache();
    __test__.resetPolicyVerifyKey();
    const app = fastify();
    registerVerifyRoutes(app);

    const allowResponse = await app.inject({
      method: "POST",
      url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
      payload: {
        presentation,
        nonce,
        audience,
        context: { space_id: spaceA }
      }
    });
    assert.equal(allowResponse.statusCode, 200);
    const allowBody = allowResponse.json() as { decision?: string };
    // #region agent log
    fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
      body: JSON.stringify({
        sessionId: "6783de",
        runId: "guardrails-pre-fix",
        hypothesisId: "H3",
        location: "verify.guardrails.test.ts:646",
        message: "space binding allow-path response",
        data: { statusCode: allowResponse.statusCode, decision: allowBody.decision },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
    assert.equal(allowBody.decision, "ALLOW");

    const nonceMismatch = makeNonce();
    await seedChallenge({
      db,
      actionId,
      policyId,
      policyVersion: 2,
      policyHash,
      nonce: nonceMismatch,
      audience
    });
    const denyResponse = await app.inject({
      method: "POST",
      url: `/v1/verify?action=${encodeURIComponent(actionId)}`,
      payload: {
        presentation: await createPresentation({
          issuerJwk: issuerPrivateJwk,
          holderPublicJwk,
          holderPrivateJwk,
          subjectDid,
          issuerDid,
          vct,
          nonce: nonceMismatch,
          audience,
          claims: {
            poster: true,
            space_id: spaceA
          },
          selectiveDisclosure: ["space_id"]
        }),
        nonce: nonceMismatch,
        audience,
        context: { space_id: spaceB }
      }
    });
    assert.equal(denyResponse.statusCode, 200);
    const denyBody = denyResponse.json() as { decision?: string; reasons?: string[] };
    assert.equal(denyBody.decision, "DENY");
    assert.ok(denyBody.reasons?.includes("space_context_mismatch"));
    await app.close();
  } finally {
    await db.destroy();
  }
});
