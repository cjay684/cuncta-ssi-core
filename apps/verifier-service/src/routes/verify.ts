import { FastifyInstance } from "fastify";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { z } from "zod";
import { verifySdJwtVc } from "@cuncta/sdjwt";
import { config } from "../config.js";
import { log } from "../log.js";
import { sha256Hex, sha256Base64Url } from "../crypto/sha256.js";
import { getDb } from "../db.js";
import { hashCanonicalJson, makeErrorResponse } from "@cuncta/shared";
import { executeObligations } from "../obligations/execute.js";
import { metrics } from "../metrics.js";
import { verifyStatusListEntry } from "../statusList.js";
import { getDidHashes } from "../pseudonymizer.js";
import { assertEd25519Jwk } from "../crypto/jwk.js";

const recordInvalidDecision = (actionId: string, decision: "ALLOW" | "DENY") => {
  if (decision === "DENY") {
    metrics.incCounter("verify_invalid_total", { action: actionId });
    metrics.incCounter("verify_denied_total", { action: actionId });
  }
};

const obligationSchema = z
  .object({
    type: z.string().min(1)
  })
  .passthrough();

const requirementsResponseSchema = z.object({
  action: z.string(),
  policyId: z.string().optional(),
  policyVersion: z.number().optional(),
  binding: z
    .object({
      mode: z.enum(["kb-jwt", "nonce"]),
      require: z.boolean()
    })
    .optional(),
  requirements: z.array(
    z.object({
      vct: z.string(),
      issuer: z
        .object({
          mode: z.enum(["allowlist", "env"]),
          allowed: z.array(z.string()).optional(),
          env: z.string().optional()
        })
        .optional(),
      disclosures: z.array(z.string()).default([]),
      revocation: z.object({ required: z.boolean() }).optional(),
      predicates: z
        .array(
          z.object({
            path: z.string(),
            op: z.enum(["eq", "neq", "gte", "lte", "in", "exists"]),
            value: z.unknown().optional()
          })
        )
        .default([]),
      presentation_templates: z.record(z.string(), z.unknown()).optional()
    })
  ),
  obligations: z.array(obligationSchema).default([])
});

const predicateSchema = z.object({
  path: z.string().min(1),
  op: z.enum(["eq", "neq", "gte", "lte", "in", "exists"]),
  value: z.unknown().optional()
});

const requirementSchema = z.object({
  vct: z.string().min(1),
  issuer: z
    .object({
      mode: z.enum(["allowlist", "env"]),
      allowed: z.array(z.string()).optional(),
      env: z.string().optional()
    })
    .optional(),
  disclosures: z.array(z.string()).default([]),
  predicates: z.array(predicateSchema).default([]),
  revocation: z.object({ required: z.boolean() }).optional()
});

const policyLogicSchema = z.object({
  binding: z
    .object({
      mode: z.enum(["kb-jwt", "nonce"]).default("kb-jwt"),
      require: z.boolean().default(true)
    })
    .optional(),
  requirements: z.array(requirementSchema).default([]),
  obligations: z.array(obligationSchema).default([])
});

const verifyBodySchema = z.object({
  presentation: z.string().min(10).max(config.VERIFY_MAX_PRESENTATION_BYTES),
  nonce: z.string().min(10).max(config.VERIFY_MAX_NONCE_CHARS),
  audience: z.string().min(3).max(config.VERIFY_MAX_AUDIENCE_CHARS)
});

const jwksSchema = z.object({
  keys: z.array(z.record(z.string(), z.unknown())).min(1)
});

let cachedKeys: Record<string, unknown>[] | null = null;
let cachedAt = 0;
let cachedPolicyVerifyKey: Awaited<ReturnType<typeof importJWK>> | null = null;

const loadPolicyVerifyKey = async () => {
  if (cachedPolicyVerifyKey) return cachedPolicyVerifyKey;
  if (!config.POLICY_SIGNING_JWK) {
    throw new Error("policy_integrity_failed");
  }
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(config.POLICY_SIGNING_JWK) as Record<string, unknown>;
  } catch {
    throw new Error("policy_integrity_failed");
  }
  const { d, ...publicJwk } = parsed as { d?: string };
  void d;
  cachedPolicyVerifyKey = await importJWK(publicJwk, "EdDSA");
  return cachedPolicyVerifyKey;
};

const verifyPolicySignature = async (policyHash: string, signature: string) => {
  const key = await loadPolicyVerifyKey();
  const { payload } = await jwtVerify(signature, key);
  if (!payload || typeof payload !== "object") {
    throw new Error("policy_integrity_failed");
  }
  if (payload.hash !== policyHash) {
    throw new Error("policy_integrity_failed");
  }
};

const loadIssuerKeys = async (forceRefresh = false) => {
  if (config.ISSUER_JWKS) {
    const parsed = jwksSchema.parse(JSON.parse(config.ISSUER_JWKS));
    return parsed.keys;
  }
  const now = Date.now();
  if (!forceRefresh && cachedKeys && now - cachedAt < 300_000) {
    return cachedKeys;
  }
  if (forceRefresh) {
    metrics.incCounter("jwks_cache_refresh_total", { reason: "kid_miss" });
  }
  const response = await fetch(`${config.ISSUER_SERVICE_BASE_URL}/jwks.json`);
  if (!response.ok) {
    throw new Error("jwks_fetch_failed");
  }
  const parsed = jwksSchema.parse(await response.json());
  cachedKeys = parsed.keys;
  cachedAt = now;
  return parsed.keys;
};

const selectKey = async (kid?: string) => {
  const keys = await loadIssuerKeys();
  const selected = !kid ? keys[0] : keys.find((key) => key.kid === kid);
  if (!selected && kid) {
    metrics.incCounter("jwks_kid_miss_total");
    const refreshed = await loadIssuerKeys(true);
    const retried = refreshed.find((key) => key.kid === kid);
    if (!retried) {
      throw new Error("jwks_kid_not_found");
    }
    return assertEd25519Jwk(retried as Record<string, unknown>, "issuer");
  }
  if (!selected) {
    throw new Error("jwks_missing");
  }
  return assertEd25519Jwk(selected as Record<string, unknown>, "issuer");
};

const getPolicyVersionFloor = async (actionId: string) => {
  const db = await getDb();
  const row = await db("policy_version_floor").where({ action_id: actionId }).first();
  return Number(row?.min_version ?? 0);
};

const getByPath = (obj: Record<string, unknown>, path: string) => {
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object") {
      return undefined;
    }
    const record = current as Record<string, unknown>;
    current = record[part];
  }
  return current;
};

const evaluatePredicate = (
  predicate: { path: string; op: string; value?: unknown },
  claims: Record<string, unknown>
) => {
  const value = getByPath(claims, predicate.path);
  switch (predicate.op) {
    case "exists":
      return value !== undefined;
    case "eq":
      return value === predicate.value;
    case "neq":
      return value !== predicate.value;
    case "in":
      return Array.isArray(predicate.value) && predicate.value.includes(value);
    case "gte":
      return typeof value === "number" && typeof predicate.value === "number"
        ? value >= predicate.value
        : false;
    case "lte":
      return typeof value === "number" && typeof predicate.value === "number"
        ? value <= predicate.value
        : false;
    default:
      return false;
  }
};

const fetchRequirements = async (action: string) => {
  const response = await fetch(`${config.POLICY_SERVICE_BASE_URL}/v1/policy/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action })
  });
  if (!response.ok) {
    throw new Error("requirements_fetch_failed");
  }
  return requirementsResponseSchema.parse(await response.json());
};

export const registerVerifyRoutes = (app: FastifyInstance) => {
  app.post("/v1/verify", async (request, reply) => {
    const action = z.object({ action: z.string().min(1) }).parse(request.query);
    const body = verifyBodySchema.parse(request.body);
    const presentationBytes = Buffer.byteLength(body.presentation, "utf8");
    if (presentationBytes > config.VERIFY_MAX_PRESENTATION_BYTES) {
      metrics.incCounter("verify_payload_too_large_total", { action: action.action });
      return reply.code(413).send(
        makeErrorResponse("invalid_request", "Presentation too large", {
          devMode: config.DEV_MODE
        })
      );
    }
    const tokenHash = sha256Hex(body.presentation);
    const requestId = (request as { requestId?: string }).requestId;
    log.info("verify.request", { requestId, action: action.action, tokenHash });

    try {
      const db = await getDb();
      const challengeHash = sha256Hex(body.nonce);
      const challengeRow = await db("verification_challenges")
        .where({ challenge_hash: challengeHash, action_id: action.action })
        .first();
      let requirements: z.infer<typeof requirementsResponseSchema> | null = null;
      let policyLogic: z.infer<typeof policyLogicSchema> | null = null;
      let pinnedPolicyId: string | null = null;
      let pinnedPolicyVersion: number | null = null;
      const hasPinnedPolicy = Boolean(challengeRow?.policy_id && challengeRow?.policy_version);
      if (hasPinnedPolicy) {
        pinnedPolicyId = challengeRow?.policy_id as string;
        pinnedPolicyVersion = Number(challengeRow?.policy_version);
        const floorVersion = config.POLICY_VERSION_FLOOR_ENFORCED
          ? await getPolicyVersionFloor(action.action)
          : 0;
        if (floorVersion > 0 && pinnedPolicyVersion < floorVersion) {
          return reply.send({
            decision: "DENY",
            reasons: ["policy_version_downgrade"],
            obligationExecutionId: null,
            obligationsExecuted: []
          });
        }
        const policyRow = await db("policies")
          .where({ policy_id: pinnedPolicyId, version: pinnedPolicyVersion })
          .first();
        if (!policyRow || policyRow.action_id !== action.action) {
          return reply.code(404).send(
            makeErrorResponse("policy_not_found", "Policy not found", {
              devMode: config.DEV_MODE
            })
          );
        }
        const logicRaw = policyRow.logic as unknown;
        const logic =
          typeof logicRaw === "string"
            ? (JSON.parse(logicRaw) as Record<string, unknown>)
            : (logicRaw as Record<string, unknown>);
        const policyHash = hashCanonicalJson({
          policy_id: policyRow.policy_id,
          action_id: policyRow.action_id,
          version: policyRow.version,
          enabled: policyRow.enabled,
          logic
        });
        try {
          if (!policyRow.policy_signature) {
            throw new Error("policy_integrity_failed");
          }
          await verifyPolicySignature(policyHash, policyRow.policy_signature as string);
          if (!challengeRow?.policy_hash || challengeRow.policy_hash !== policyHash) {
            throw new Error("policy_integrity_failed");
          }
        } catch {
          return reply.code(503).send(
            makeErrorResponse("policy_integrity_failed", "Policy integrity check failed", {
              devMode: config.DEV_MODE
            })
          );
        }
        policyLogic = policyLogicSchema.parse(logic);
      } else {
        try {
          requirements = await fetchRequirements(action.action);
          if (!requirements.policyId || !requirements.policyVersion) {
            return reply.code(409).send(
              makeErrorResponse("challenge_invalid", "Challenge policy not pinned", {
                devMode: config.DEV_MODE
              })
            );
          }
          pinnedPolicyId = requirements.policyId;
          pinnedPolicyVersion = requirements.policyVersion;
          const floorVersion = config.POLICY_VERSION_FLOOR_ENFORCED
            ? await getPolicyVersionFloor(action.action)
            : 0;
          if (floorVersion > 0 && pinnedPolicyVersion < floorVersion) {
            return reply.send({
              decision: "DENY",
              reasons: ["policy_version_downgrade"],
              obligationExecutionId: null,
              obligationsExecuted: []
            });
          }
        } catch (error) {
          log.error("verify.requirements.failed", { requestId, error, action: action.action });
          return reply.code(502).send(
            makeErrorResponse("internal_error", "Policy unavailable", {
              devMode: config.DEV_MODE
            })
          );
        }
      }

      const activeRequirements = policyLogic?.requirements ?? requirements?.requirements ?? [];
      const activeObligations = policyLogic?.obligations ?? requirements?.obligations ?? [];
      const hasRequirements = activeRequirements.length > 0;
      const reasons: string[] = [];
      let decision: "ALLOW" | "DENY" = "ALLOW";
      let subjectHash = sha256Hex(tokenHash);
      let subjectHashLegacy: string | null = null;
      let payload: Record<string, unknown> | null = null;
      let sdJwtPresentation = "";
      let challengeValid = false;
      let allowObligations = true;

      const deny = (reason: string) => {
        if (decision !== "DENY") {
          decision = "DENY";
        }
        reasons.push(reason);
      };

      if (decision === "ALLOW" && hasRequirements) {
        if (!challengeRow) {
          deny("challenge_not_found");
        } else if (challengeRow.audience && challengeRow.audience !== body.audience) {
          deny("aud_mismatch");
        } else if (challengeRow.consumed_at) {
          deny("challenge_consumed");
        } else if (challengeRow.expires_at && new Date(challengeRow.expires_at) <= new Date()) {
          deny("challenge_expired");
        } else {
          challengeValid = true;
        }
      }

      const parts = body.presentation.split("~");
      const jwt = parts[0];
      const kbJwt = parts.at(-1) ?? "";
      const sdParts = parts.slice(0, -1);
      while (sdParts.length && sdParts.at(-1) === "") {
        sdParts.pop();
      }
      sdJwtPresentation = `${sdParts.join("~")}~`;
      const disclosureCount = sdParts.slice(1).filter((value) => value.length > 0).length;
      if (disclosureCount > config.VERIFY_MAX_DISCLOSURES) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Presentation disclosures exceed limit", {
            devMode: config.DEV_MODE
          })
        );
      }

      if (decision === "ALLOW") {
        if (!kbJwt) {
          deny("kb_jwt_missing");
        } else {
          try {
            const kbHeader = decodeProtectedHeader(kbJwt);
            if (kbHeader.alg !== "EdDSA") {
              deny("kb_jwt_invalid_alg");
            } else {
              const kbDecoded = decodeJwt(kbJwt) as Record<string, unknown>;
              const cnf = kbDecoded.cnf as { jwk?: Record<string, unknown> } | undefined;
              if (!cnf?.jwk) {
                deny("kb_jwt_missing_cnf");
              } else {
                const holderJwk = assertEd25519Jwk(cnf.jwk, "holder");
                const holderKey = await importJWK(holderJwk as never, "EdDSA");
                const kbPayload = await jwtVerify(kbJwt, holderKey).catch(() => null);
                if (!kbPayload) {
                  deny("binding_invalid");
                } else {
                  if (typeof kbPayload.payload.exp !== "number") {
                    deny("kb_jwt_missing_exp");
                  }
                  const kbAud = kbPayload.payload.aud;
                  const audValid = Array.isArray(kbAud)
                    ? kbAud.map(String).includes(body.audience)
                    : typeof kbAud === "string" && kbAud === body.audience;
                  if (!audValid) {
                    deny(typeof kbAud === "undefined" ? "kb_jwt_missing_aud" : "aud_mismatch");
                  }
                  const kbNonce = kbPayload.payload.nonce;
                  if (typeof kbNonce !== "string") {
                    deny("kb_jwt_missing_nonce");
                  } else if (kbNonce !== body.nonce) {
                    deny("nonce_mismatch");
                  }
                  const sdHash = kbPayload.payload.sd_hash;
                  if (typeof sdHash !== "string") {
                    deny("kb_jwt_missing_sd_hash");
                  } else {
                    const expectedHash = sha256Base64Url(sdJwtPresentation);
                    if (sdHash !== expectedHash) {
                      deny("sd_hash_mismatch");
                    }
                  }
                }
              }
            }
          } catch {
            deny("kb_jwt_invalid");
          }
        }
      }

      if (decision === "ALLOW" && hasRequirements) {
        const header = decodeProtectedHeader(jwt);
        const jwksForVerify = header.kid
          ? { keys: [(await selectKey(header.kid)) as never] }
          : { keys: (await loadIssuerKeys()) as never[] };
        const result = await verifySdJwtVc({
          token: sdJwtPresentation,
          jwks: jwksForVerify,
          allowLegacyTyp: false
        });

        payload = result.payload;
        if (typeof payload.sub !== "string" || !payload.sub.startsWith("did:")) {
          deny("missing_subject");
          allowObligations = false;
        } else {
          const hashes = getDidHashes(payload.sub);
          subjectHash = hashes.primary;
          subjectHashLegacy = hashes.legacy;
          const tombstone = await db("privacy_tombstones")
            .whereIn("did_hash", [subjectHash, subjectHashLegacy].filter(Boolean))
            .first();
          if (tombstone) {
            deny("privacy_erased");
            allowObligations = false;
          }
        }
        const status = payload.status as Record<string, unknown> | undefined;
        if (!status) {
          deny("missing_status");
        }

        const requirement = activeRequirements.find((req) => req.vct === payload?.vct);
        if (!requirement) {
          deny("vct_mismatch");
        }

        if (decision === "ALLOW" && requirement?.issuer) {
          const issuerDid = payload?.iss as string | undefined;
          if (!issuerDid) {
            deny("issuer_missing");
          } else if (requirement.issuer.mode === "allowlist") {
            const allowed = requirement.issuer.allowed ?? [];
            if (!(allowed.includes("*") || allowed.includes(issuerDid))) {
              deny("issuer_not_allowed");
            }
          } else if (requirement.issuer.mode === "env") {
            const envDid = requirement.issuer.env ? process.env[requirement.issuer.env] : undefined;
            if (!envDid || envDid !== issuerDid) {
              deny("issuer_not_allowed");
            }
          }
        }

        if (decision === "ALLOW" && requirement) {
          const requiredDisclosuresOk = requirement.disclosures.every(
            (path) => getByPath(result.claims, path) !== undefined
          );
          if (!requiredDisclosuresOk) {
            deny("required_disclosure_missing");
          }
        }

        if (decision === "ALLOW" && requirement) {
          const predicatesOk = requirement.predicates.every((predicate) =>
            evaluatePredicate(predicate, result.claims)
          );
          if (!predicatesOk) {
            deny("predicate_failed");
          }
        }

        if (decision === "ALLOW" && requirement?.revocation?.required !== false) {
          const statusCheck = await verifyStatusListEntry(status as Record<string, unknown>);
          if (!statusCheck.valid) {
            deny(statusCheck.reason ?? "revoked");
          }
        }

        if (decision === "ALLOW") {
          const consumed = await db("verification_challenges")
            .where({ challenge_hash: challengeHash, action_id: action.action })
            .whereNull("consumed_at")
            .andWhere("expires_at", ">", new Date().toISOString())
            .update({ consumed_at: new Date().toISOString() });
          if (!consumed) {
            deny("challenge_consumed");
            challengeValid = false;
          }
        }
      }

      if (challengeValid && allowObligations) {
        const obligationsResult = await executeObligations({
          actionId: action.action,
          policyId: pinnedPolicyId ?? requirements?.policyId ?? "unknown",
          policyVersion: pinnedPolicyVersion ?? requirements?.policyVersion ?? 0,
          decision,
          subjectDidHash: subjectHash,
          subjectDidHashLegacy: subjectHashLegacy,
          tokenHash: tokenHash,
          challengeHash,
          obligations: activeObligations
        });

        if (decision === "ALLOW" && obligationsResult.blockedReason) {
          decision = "DENY";
          reasons.push(obligationsResult.blockedReason);
        }

        metrics.incCounter("verify_decisions_total", {
          action: action.action,
          decision
        });
        recordInvalidDecision(action.action, decision);
        return reply.send({
          decision,
          reasons,
          obligationExecutionId: obligationsResult.executionId,
          obligationsExecuted: obligationsResult.obligations
        });
      }

      metrics.incCounter("verify_decisions_total", {
        action: action.action,
        decision
      });
      recordInvalidDecision(action.action, decision);
      return reply.send({
        decision,
        reasons,
        obligationExecutionId: null,
        obligationsExecuted: []
      });
    } catch (error) {
      log.error("verify.failed", { requestId, error });
      metrics.incCounter("verify_invalid_total", { action: action.action });
      if (error instanceof Error && error.message === "jwks_kid_not_found") {
        return reply.send({ decision: "DENY", reasons: ["jwks_kid_not_found"] });
      }
      return reply.send({ decision: "DENY", reasons: ["verification_failed"] });
    }
  });
};

export const __test__ = {
  selectKey,
  resetIssuerKeyCache: () => {
    cachedKeys = null;
    cachedAt = 0;
  },
  resetPolicyVerifyKey: () => {
    cachedPolicyVerifyKey = null;
  }
};
