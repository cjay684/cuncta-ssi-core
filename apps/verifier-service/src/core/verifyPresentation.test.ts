import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createDb, runMigrations } from "@cuncta/db";
import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from "jose";
import { hashCanonicalJson } from "@cuncta/shared";

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

test(
  "verifyPresentationCore: policy floor denies pinned downgraded policy versions",
  { concurrency: false },
  async () => {
    process.env.NODE_ENV = "development";
    process.env.POLICY_VERSION_FLOOR_ENFORCED = "true";
    process.env.VERIFY_MAX_PRESENTATION_BYTES = "65536";
    process.env.ENFORCE_ORIGIN_AUDIENCE = "false";
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
      const audience = `cuncta.action:${actionId}`;
      const nonce = makeNonce();

      await db("verification_challenges").del();
      await db("policy_version_floor").where({ action_id: actionId }).del();
      await db("policies").where({ action_id: actionId }).del();
      await db("actions").where({ action_id: actionId }).del();

      await db("actions").insert({
        action_id: actionId,
        description: "core floor test",
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
      config.ENFORCE_ORIGIN_AUDIENCE = false;
      config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
      config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://127.0.0.1:1";

      const { verifyPresentationCore, __test__ } = await import("./verifyPresentation.js");
      __test__.resetIssuerKeyCache();
      __test__.resetPolicyVerifyKey();

      const result = await verifyPresentationCore({
        actionId,
        audience,
        nonce,
        presentation: "xxxxxxxxxx"
      });
      assert.equal(result.decision, "DENY");
      assert.ok(result.reasons.includes("policy_version_downgrade"));
    } finally {
      await db.destroy();
    }
  }
);

test(
  "verifyPresentationCore: consumes challenge on first attempt even when later DENY",
  { concurrency: false },
  async () => {
    process.env.NODE_ENV = "development";
    process.env.POLICY_VERSION_FLOOR_ENFORCED = "true";
    process.env.VERIFY_MAX_PRESENTATION_BYTES = "65536";
    process.env.ENFORCE_ORIGIN_AUDIENCE = "false";
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
        description: "core consume test",
        created_at: nowIso(),
        updated_at: nowIso()
      });

      const policyId = `policy.consume.${randomUUID()}.v2`;
      const policyHash = await seedPolicy({
        db,
        actionId,
        policyId,
        version: 2,
        logic: {
          requirements: [
            {
              vct: `cuncta.identity.${randomUUID()}`,
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

      const { config } = await import("../config.js");
      config.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK;
      config.POLICY_VERSION_FLOOR_ENFORCED = true;
      config.VERIFY_MAX_PRESENTATION_BYTES = 65536;
      config.ENFORCE_ORIGIN_AUDIENCE = false;
      config.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://127.0.0.1:1";
      config.POLICY_SERVICE_BASE_URL = process.env.POLICY_SERVICE_BASE_URL ?? "http://127.0.0.1:1";

      const { verifyPresentationCore, __test__ } = await import("./verifyPresentation.js");
      __test__.resetIssuerKeyCache();
      __test__.resetPolicyVerifyKey();

      const configSnapshot = {
        POLICY_SIGNING_JWK: config.POLICY_SIGNING_JWK?.slice(0, 40),
        POLICY_VERSION_FLOOR_ENFORCED: config.POLICY_VERSION_FLOOR_ENFORCED,
        ENFORCE_ORIGIN_AUDIENCE: config.ENFORCE_ORIGIN_AUDIENCE
      };
      console.log("TEST_DIAG:config_snapshot", JSON.stringify(configSnapshot));

      const challengeBeforeVerify = await db("verification_challenges")
        .where({
          action_id: actionId,
          challenge_hash: createHash("sha256").update(nonce).digest("hex")
        })
        .first();
      console.log(
        "TEST_DIAG:challenge_before_verify",
        JSON.stringify({
          exists: Boolean(challengeBeforeVerify),
          policy_id: challengeBeforeVerify?.policy_id,
          policy_version: challengeBeforeVerify?.policy_version,
          policy_hash: challengeBeforeVerify?.policy_hash?.slice(0, 16)
        })
      );

      const policyBeforeVerify = await db("policies").where({ policy_id: policyId }).first();
      console.log(
        "TEST_DIAG:policy_before_verify",
        JSON.stringify({
          exists: Boolean(policyBeforeVerify),
          policy_id: policyBeforeVerify?.policy_id,
          version: policyBeforeVerify?.version,
          enabled: policyBeforeVerify?.enabled,
          has_signature: Boolean(policyBeforeVerify?.policy_signature),
          policy_hash: policyBeforeVerify?.policy_hash?.slice(0, 16),
          logic_type: typeof policyBeforeVerify?.logic
        })
      );

      const first = await verifyPresentationCore({
        actionId,
        audience,
        nonce,
        presentation: "presentation-token~"
      });
      console.log("TEST_DIAG:first_result", JSON.stringify(first));
      assert.equal(first.decision, "DENY", `expected DENY, got ${first.decision}`);
      assert.ok(
        first.reasons.includes("kb_jwt_missing"),
        `expected reasons to include kb_jwt_missing but got: ${JSON.stringify(first.reasons)}`
      );

      const row = await db("verification_challenges")
        .where({
          action_id: actionId,
          challenge_hash: createHash("sha256").update(nonce).digest("hex")
        })
        .first();
      assert.ok(
        row?.consumed_at,
        `expected consumed_at to be set, consumed_at=${row?.consumed_at}, row_exists=${Boolean(row)}`
      );

      const second = await verifyPresentationCore({
        actionId,
        audience,
        nonce,
        presentation: "presentation-token~"
      });
      assert.equal(second.decision, "DENY");
      assert.ok(second.reasons.includes("challenge_consumed"));
    } finally {
      await db.destroy();
    }
  }
);
