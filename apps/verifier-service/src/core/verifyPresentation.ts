import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { z } from "zod";
import { verifySdJwtVc } from "@cuncta/sdjwt";
import { canonicalizeJson, hashCanonicalJson } from "@cuncta/shared";
import { verifyDiBbsCredential, verifyDiBbsPresentation } from "@cuncta/di-bbs";
import { config } from "../config.js";
import { log } from "../log.js";
import { sha256Hex, sha256Base64Url } from "../crypto/sha256.js";
import { getDb } from "../db.js";
import { executeObligations } from "../obligations/execute.js";
import { metrics } from "../metrics.js";
import { verifyStatusListEntry } from "../statusList.js";
import { getDidHashes } from "../pseudonymizer.js";
import { assertEd25519Jwk } from "../crypto/jwk.js";
import { resolveDidDocument } from "../didResolver.js";
import { isCnfKeyAuthorizedByDidDocument } from "@cuncta/shared";
import { verifyRequiredZkPredicates } from "../zk/verifyZkPredicates.js";
import { flagsFromRequirements, selectComplianceProfile } from "../complianceProfiles.js";
import { checkIssuerRule } from "./issuerTrust.js";

export type VerifyPresentationCoreInput = {
  presentation: string;
  nonce: string;
  audience: string;
  actionId: string;
  context?: Record<string, unknown>;
  verifierOrigin?: string;
  requestHash?: string;
  requestJwt?: string;
  zkProofs?: unknown;
};

type DiBbsEnvelope = {
  format: "di+bbs";
  request_hash: string;
  subject_did: string;
  credential: unknown;
  presentation: unknown;
  kb_jwt: string;
};


const toBytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));

const deriveBindingPayloadHash = (payload: unknown) => sha256Base64Url(canonicalizeJson(payload));

const sha256HexFromString = (value: string) => sha256Hex(value);

const deriveBbsNonce = (input: { nonce: string; audience: string; requestHash: string }) => {
  const hex = sha256HexFromString(`${input.audience}|${input.nonce}|${input.requestHash}`);
  return toBytes(hex);
};

const fetchJsonWithTimeout = async <T>(url: string, timeoutMs = 10_000): Promise<T> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("timeout"), timeoutMs);
  try {
    const res = await fetch(url, { method: "GET", signal: controller.signal });
    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`http_${res.status}:${text}`);
    }
    return (await res.json()) as T;
  } finally {
    clearTimeout(timer);
  }
};

let cachedIssuerBbsPublicKeyB64u: string | null = null;
const getIssuerBbsPublicKeyB64u = async () => {
  if (cachedIssuerBbsPublicKeyB64u !== null) return cachedIssuerBbsPublicKeyB64u;
  const url = `${config.ISSUER_SERVICE_BASE_URL.replace(/\/$/, "")}/.well-known/openid-credential-issuer`;
  const meta = await fetchJsonWithTimeout<{ issuer_bbs_public_key_b64u?: string }>(url).catch(() => ({} as any));
  const pk = typeof meta.issuer_bbs_public_key_b64u === "string" ? meta.issuer_bbs_public_key_b64u.trim() : "";
  cachedIssuerBbsPublicKeyB64u = pk || "";
  return cachedIssuerBbsPublicKeyB64u;
};

export type VerifyPresentationCoreResult = {
  decision: "ALLOW" | "DENY";
  reasons: string[];
  policyId?: string;
  policyVersion?: number;
  obligationsExecuted?: unknown[];
  // Kept for legacy `/v1/verify` adapter response shape.
  obligationExecutionId?: string | null;
};

type CoreHttpErrorShape = { statusCode: number; code: string; message: string };

class CoreHttpError extends Error implements CoreHttpErrorShape {
  statusCode: number;
  code: string;
  constructor(input: CoreHttpErrorShape) {
    super(input.message);
    this.statusCode = input.statusCode;
    this.code = input.code;
  }
}

export const dependencyFailureDeny = () => ({
  decision: "DENY" as const,
  reasons: ["not_allowed"],
  obligationExecutionId: null as null,
  obligationsExecuted: [] as unknown[]
});

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
  profileId: z.string().optional(),
  profileFlags: z
    .object({
      enforceOriginAudience: z.boolean().optional(),
      failClosedDependencies: z.boolean().optional(),
      statusListStrict: z.boolean().optional()
    })
    .optional(),
  context: z.record(z.string(), z.unknown()).optional(),
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
          mode: z.enum(["allowlist", "env", "trust_registry"]),
          allowed: z.array(z.string()).optional(),
          env: z.string().optional(),
          registry_id: z.string().optional(),
          trust_mark: z.string().optional()
        })
        .optional(),
      formats: z.array(z.string()).default(["dc+sd-jwt"]),
      zk_predicates: z
        .array(
          z.object({
            id: z.string().min(1),
            params: z.record(z.string(), z.unknown()).optional()
          })
        )
        .default([]),
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
      context_predicates: z
        .array(
          z.object({
            left: z.string().min(1),
            right: z.string().min(1),
            op: z.enum(["eq"])
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
      mode: z.enum(["allowlist", "env", "trust_registry"]),
      allowed: z.array(z.string()).optional(),
      env: z.string().optional(),
      registry_id: z.string().optional(),
      trust_mark: z.string().optional()
    })
    .optional(),
  formats: z.array(z.string()).default(["dc+sd-jwt"]),
  zk_predicates: z
    .array(
      z.object({
        id: z.string().min(1),
        params: z.record(z.string(), z.unknown()).optional()
      })
    )
    .default([]),
  disclosures: z.array(z.string()).default([]),
  predicates: z.array(predicateSchema).default([]),
  context_predicates: z
    .array(
      z.object({
        left: z.string().min(1),
        right: z.string().min(1),
        op: z.enum(["eq"])
      })
    )
    .default([]),
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

const applyComplianceOverlayToPolicyLogic = (
  profile: { overlay?: { binding?: { require?: true; mode?: "kb-jwt" }; requirements?: { revocationRequired?: true } } },
  logic: z.infer<typeof policyLogicSchema>
) => {
  const overlay = profile.overlay ?? {};
  const next = {
    ...logic,
    binding: logic.binding ? { ...logic.binding } : undefined,
    requirements: (logic.requirements ?? []).map((r) => ({ ...r })),
    obligations: (logic.obligations ?? []).map((o) => ({ ...o }))
  };
  if (overlay.binding?.require) {
    next.binding = { ...(next.binding ?? { mode: "kb-jwt", require: true }), require: true };
  }
  if (overlay.binding?.mode) {
    next.binding = { ...(next.binding ?? { mode: "kb-jwt", require: true }), mode: "kb-jwt" };
  }
  if (overlay.requirements?.revocationRequired) {
    for (const req of next.requirements) {
      req.revocation = { ...(req.revocation ?? { required: true }), required: true };
    }
  }
  return next;
};

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
  const parseIso = (v: unknown) => {
    if (typeof v !== "string") return null;
    const s = v.trim();
    if (!s) return null;
    const ms = Date.parse(s);
    return Number.isFinite(ms) ? ms : null;
  };
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
      if (typeof value === "number" && typeof predicate.value === "number") {
        return value >= predicate.value;
      }
      // Freshness checks for ISO timestamps (e.g. capability `as_of`).
      // This stays strict: only compare when BOTH sides parse as valid timestamps.
      {
        const a = parseIso(value);
        const b = parseIso(predicate.value);
        return a !== null && b !== null ? a >= b : false;
      }
    case "lte":
      if (typeof value === "number" && typeof predicate.value === "number") {
        return value <= predicate.value;
      }
      {
        const a = parseIso(value);
        const b = parseIso(predicate.value);
        return a !== null && b !== null ? a <= b : false;
      }
    default:
      return false;
  }
};

const fetchRequirements = async (action: string, context?: Record<string, unknown>) => {
  const response = await fetch(`${config.POLICY_SERVICE_BASE_URL}/v1/policy/evaluate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action, context })
  });
  if (!response.ok) {
    throw new Error("requirements_fetch_failed");
  }
  return requirementsResponseSchema.parse(await response.json());
};

const evaluateContextPredicate = (
  predicate: { left: string; right: string; op: "eq" },
  context: Record<string, unknown>,
  claims: Record<string, unknown>
) => {
  const leftValue = getByPath({ context, claims }, predicate.left);
  const rightValue = getByPath({ context, claims }, predicate.right);
  if (predicate.op === "eq") {
    return leftValue !== undefined && rightValue !== undefined && leftValue === rightValue;
  }
  return false;
};

export const verifyPresentationCore = async (
  input: VerifyPresentationCoreInput
): Promise<VerifyPresentationCoreResult> => {
  const presentationBytes = Buffer.byteLength(input.presentation, "utf8");
  if (presentationBytes > config.VERIFY_MAX_PRESENTATION_BYTES) {
    metrics.incCounter("verify_payload_too_large_total", { action: input.actionId });
    throw new CoreHttpError({
      statusCode: 413,
      code: "invalid_request",
      message: "Presentation too large"
    });
  }

  const tokenHash = sha256Hex(input.presentation);
  const requestId = undefined as string | undefined;
  void requestId;
  const selectedProfile = selectComplianceProfile(input.context);
  let effectiveProfileFlags = flagsFromRequirements({ profile: selectedProfile, requirementsFlags: null });

  try {
    const db = await getDb();
    const challengeHash = sha256Hex(input.nonce);
    const challengeRow = await db("verification_challenges")
      .where({ challenge_hash: challengeHash, action_id: input.actionId })
      .first();
    let requirements: z.infer<typeof requirementsResponseSchema> | null = null;
    let policyLogic: z.infer<typeof policyLogicSchema> | null = null;
    let pinnedPolicyId: string | null = null;
    let pinnedPolicyVersion: number | null = null;
    const hasPinnedPolicy = Boolean(challengeRow?.policy_id && challengeRow?.policy_version);
    if (hasPinnedPolicy) {
      pinnedPolicyId = challengeRow?.policy_id as string;
      pinnedPolicyVersion = Number(challengeRow?.policy_version);
      const floorVersion = config.POLICY_VERSION_FLOOR_ENFORCED ? await getPolicyVersionFloor(input.actionId) : 0;
      if (floorVersion > 0 && pinnedPolicyVersion < floorVersion) {
        return {
          decision: "DENY",
          reasons: ["policy_version_downgrade"],
          policyId: pinnedPolicyId ?? undefined,
          policyVersion: pinnedPolicyVersion ?? undefined,
          obligationExecutionId: null,
          obligationsExecuted: []
        };
      }
      const policyRow = await db("policies")
        .where({ policy_id: pinnedPolicyId, version: pinnedPolicyVersion })
        .first();
      if (!policyRow || policyRow.action_id !== input.actionId) {
        throw new CoreHttpError({
          statusCode: 404,
          code: "policy_not_found",
          message: "Policy not found"
        });
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
        log.error("verify.policy.integrity_failed", { action: input.actionId });
        // Fail-closed and non-oracular: return a normal DENY response even on integrity failure.
        return dependencyFailureDeny();
      }
      policyLogic = applyComplianceOverlayToPolicyLogic(selectedProfile, policyLogicSchema.parse(logic));
    } else {
      try {
        requirements = await fetchRequirements(input.actionId, input.context);
        effectiveProfileFlags = flagsFromRequirements({
          profile: selectedProfile,
          requirementsFlags: requirements.profileFlags ?? null
        });
        if (!requirements.policyId || !requirements.policyVersion) {
          throw new CoreHttpError({
            statusCode: 409,
            code: "challenge_invalid",
            message: "Challenge policy not pinned"
          });
        }
        pinnedPolicyId = requirements.policyId;
        pinnedPolicyVersion = requirements.policyVersion;
        const floorVersion = config.POLICY_VERSION_FLOOR_ENFORCED ? await getPolicyVersionFloor(input.actionId) : 0;
        if (floorVersion > 0 && pinnedPolicyVersion < floorVersion) {
          return {
            decision: "DENY",
            reasons: ["policy_version_downgrade"],
            policyId: pinnedPolicyId ?? undefined,
            policyVersion: pinnedPolicyVersion ?? undefined,
            obligationExecutionId: null,
            obligationsExecuted: []
          };
        }
      } catch (error) {
        if (error instanceof CoreHttpError) throw error;
        log.error("verify.requirements.failed", { error, action: input.actionId });
        // Fail-closed and non-oracular: treat dependency failure as a normal deny decision.
        return dependencyFailureDeny();
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
    let claims: Record<string, unknown> = {};
    let sdJwtPresentation = "";
    let challengeValid = false;
    let allowObligations = true;
    let holderCnfJwk: Record<string, unknown> | null = null;

    const deny = (reason: string) => {
      if (decision !== "DENY") {
        decision = "DENY";
      }
      reasons.push(reason);
    };

    if (decision === "ALLOW" && (config.ENFORCE_ORIGIN_AUDIENCE || effectiveProfileFlags.enforceOriginAudience)) {
      if (!input.audience.startsWith("origin:")) {
        deny("audience_origin_required");
      }
    }

    if (decision === "ALLOW" && hasRequirements) {
      if (!challengeRow) {
        deny("challenge_not_found");
      } else if (challengeRow.audience && challengeRow.audience !== input.audience) {
        deny("aud_mismatch");
      } else if (challengeRow.consumed_at) {
        deny("challenge_consumed");
      } else if (challengeRow.expires_at && new Date(challengeRow.expires_at) <= new Date()) {
        deny("challenge_expired");
      } else {
        challengeValid = true;
      }
    }

    // Replay hardening: consume the challenge after challenge validation, before the rest of
    // verification runs. This means challenge-validation failures do not consume it, but later
    // failures (bad signature, predicate failure, revocation, etc.) still burn the challenge.
    if (decision === "ALLOW" && challengeValid) {
      const consumed = await db("verification_challenges")
        .where({ challenge_hash: challengeHash, action_id: input.actionId })
        .whereNull("consumed_at")
        .andWhere("expires_at", ">", new Date().toISOString())
        .update({ consumed_at: new Date().toISOString() });
      if (!consumed) {
        deny("challenge_consumed");
        challengeValid = false;
      }
    }

    const raw = input.presentation.trim();
    const isJsonEnvelope = raw.startsWith("{") && raw.endsWith("}");
    let kbJwt = "";
    let expectedBindingHash: string | null = null;
    let envelope: DiBbsEnvelope | null = null;
    let envelopeFormat: "di+bbs" | null = null;
    let jwt = "";

    if (isJsonEnvelope) {
      try {
        const parsed = JSON.parse(raw) as Record<string, unknown>;
        const format = String(parsed.format ?? "");
        if (format === "di+bbs") {
          if (!config.ALLOW_EXPERIMENTAL_ZK) {
            deny("zk_disabled");
          }
          envelopeFormat = format;
          if (typeof parsed.kb_jwt !== "string" || parsed.kb_jwt.length < 10) {
            deny("kb_jwt_missing");
          } else {
            kbJwt = parsed.kb_jwt;
          }
          const bindingPayload = {
            format,
            request_hash: parsed.request_hash,
            subject_did: parsed.subject_did,
            credential: parsed.credential,
            presentation: parsed.presentation
          };
          expectedBindingHash = deriveBindingPayloadHash(bindingPayload);
          envelope = parsed as never;
        } else {
          deny("presentation_format_unsupported");
        }
      } catch {
        deny("presentation_invalid");
      }
    } else {
      const parts = input.presentation.split("~");
      jwt = parts[0];
      kbJwt = parts.at(-1) ?? "";
      const sdParts = parts.slice(0, -1);
      while (sdParts.length && sdParts.at(-1) === "") {
        sdParts.pop();
      }
      sdJwtPresentation = `${sdParts.join("~")}~`;
      expectedBindingHash = sha256Base64Url(sdJwtPresentation);
      const disclosureCount = sdParts.slice(1).filter((value) => value.length > 0).length;
      if (disclosureCount > config.VERIFY_MAX_DISCLOSURES) {
        throw new CoreHttpError({
          statusCode: 400,
          code: "invalid_request",
          message: "Presentation disclosures exceed limit"
        });
      }
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
              holderCnfJwk = holderJwk as unknown as Record<string, unknown>;
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
                  ? kbAud.map(String).includes(input.audience)
                  : typeof kbAud === "string" && kbAud === input.audience;
                if (!audValid) {
                  deny(typeof kbAud === "undefined" ? "kb_jwt_missing_aud" : "aud_mismatch");
                }
                const kbNonce = kbPayload.payload.nonce;
                if (typeof kbNonce !== "string") {
                  deny("kb_jwt_missing_nonce");
                } else if (kbNonce !== input.nonce) {
                  deny("nonce_mismatch");
                }
                const sdHash = kbPayload.payload.sd_hash;
                if (typeof sdHash !== "string") {
                  deny("kb_jwt_missing_sd_hash");
                } else {
                  if (!expectedBindingHash) {
                    deny("sd_hash_required");
                  } else if (sdHash !== expectedBindingHash) {
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
      if (isJsonEnvelope) {
        if (!envelopeFormat || !envelope) {
          deny("presentation_invalid");
          allowObligations = false;
        } else {
          const env = envelope as unknown as {
            request_hash?: unknown;
            subject_did?: unknown;
            credential?: unknown;
            presentation?: unknown;
          };
          if (!input.requestHash) {
            deny("request_hash_required");
            allowObligations = false;
          } else if (String(env.request_hash ?? "") !== input.requestHash) {
            deny("request_hash_mismatch");
            allowObligations = false;
          }

          if (decision === "ALLOW" && envelopeFormat === "di+bbs") {
            // Prefer explicit configuration, but support out-of-the-box DI+BBS by fetching
            // the issuer's BBS public key from issuer metadata.
            const pubKeyB64u =
              (process.env.ISSUER_BBS_PUBLIC_KEY_B64U ?? "").trim() || (await getIssuerBbsPublicKeyB64u());
            if (!pubKeyB64u) {
              deny("bbs_key_missing");
              allowObligations = false;
            } else {
              const bbsPublicKey = Uint8Array.from(Buffer.from(pubKeyB64u, "base64url"));
              type DiCredential = Parameters<typeof verifyDiBbsCredential>[0]["credential"];
              type DiPresentation = Parameters<typeof verifyDiBbsPresentation>[0]["presentation"];
              const credential = env.credential as DiCredential;
              const presentation = env.presentation as DiPresentation;
              const subjectDid = String(env.subject_did ?? "");
              if (!subjectDid.startsWith("did:")) {
                deny("missing_subject");
                allowObligations = false;
              } else {
                const vcOk = await verifyDiBbsCredential({ credential, publicKey: bbsPublicKey }).catch(() => ({
                  ok: false
                }));
                if (!vcOk.ok) {
                  deny("di_vc_invalid_signature");
                } else {
                  const bbsNonce = deriveBbsNonce({
                    nonce: input.nonce,
                    audience: input.audience,
                    requestHash: input.requestHash ?? ""
                  });
                  const presOk = await verifyDiBbsPresentation({
                    presentation,
                    credentialSubjectAll: credential.credentialSubject as Record<string, unknown>,
                    issuer: String(credential.issuer ?? ""),
                    vct: String(credential.vct ?? ""),
                    publicKey: bbsPublicKey,
                    nonce: bbsNonce
                  }).catch(() => ({ ok: false }));
                  if (!presOk.ok) {
                    deny("di_proof_invalid");
                  } else {
                    const statusFromCredential = (credential as any)?.status;
                    payload = {
                      sub: subjectDid,
                      iss: String(credential.issuer ?? ""),
                      vct: String(credential.vct ?? ""),
                      // DI credentials carry status list data in their object form (issuer extension).
                      status:
                        statusFromCredential && typeof statusFromCredential === "object" && !Array.isArray(statusFromCredential)
                          ? (statusFromCredential as Record<string, unknown>)
                          : {}
                    };
                    claims =
                      (presentation?.revealed && typeof presentation.revealed === "object"
                        ? (presentation.revealed as Record<string, unknown>)
                        : {}) ?? {};
                  }
                }
              }
            }
          }

          // Legacy Semaphore-era `zk-age` envelope format is intentionally not supported.

          if (decision === "ALLOW" && payload?.sub) {
            const hashes = getDidHashes(String(payload.sub));
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
        }
      } else {
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
        claims = result.claims;
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
      }

      // From here onward the evaluation expects `payload` to be present.
      // If parsing/verification failed earlier, we fail-closed but keep going to
      // accumulate reasons consistently.
      if (!payload) {
        deny("presentation_invalid");
        allowObligations = false;
        payload = { sub: "", iss: "", vct: "", status: {} };
      }

      const activeBinding = policyLogic?.binding ?? requirements?.binding ?? { mode: "kb-jwt", require: true };
      if (
        decision === "ALLOW" &&
        config.ENFORCE_DID_KEY_BINDING &&
        activeBinding.mode === "kb-jwt" &&
        activeBinding.require
      ) {
        if (!holderCnfJwk) {
          deny("kb_jwt_missing_cnf");
          allowObligations = false;
        } else {
          try {
            const didDocument = await resolveDidDocument(payload.sub as string);
            const authorized = isCnfKeyAuthorizedByDidDocument(didDocument, holderCnfJwk);
            if (!authorized.ok) {
              deny(authorized.reason);
              allowObligations = false;
            }
          } catch {
            deny("did_resolution_unavailable");
            allowObligations = false;
          }
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
      const requirementExtras = requirement as unknown as { zk_predicates?: unknown };
      const zkPredicates = Array.isArray(requirementExtras?.zk_predicates) ? requirementExtras.zk_predicates : [];
      const requiresZk = zkPredicates.length > 0;

      if (decision === "ALLOW" && requirement) {
        const presentedFormat = isJsonEnvelope ? (envelopeFormat ?? "unknown") : "dc+sd-jwt";
        const allowedFormats = requirement.formats ?? ["dc+sd-jwt"];
        if (Array.isArray(allowedFormats) && allowedFormats.length > 0 && !allowedFormats.includes(presentedFormat)) {
          deny("format_mismatch");
        }
        if (requiresZk && !config.ALLOW_EXPERIMENTAL_ZK) {
          deny("zk_disabled");
          allowObligations = false;
        }
        if (requiresZk) {
          // Proofs arrive via `zk_proofs` extension claim on the direct_post.jwt response.
          // The presence/validity is checked later once we have `claims` and `requestHash`.
        }
      }

      if (decision === "ALLOW" && requirement?.issuer) {
        const issuerDid = payload?.iss as string | undefined;
        if (!issuerDid) {
          deny("issuer_missing");
        } else {
          const issuerCheck = await checkIssuerRule({
            issuerDid,
            rule: requirement.issuer as never
          });
          if (!issuerCheck.ok) {
            deny(issuerCheck.reason);
          }
        }
      }

      if (decision === "ALLOW" && requirement) {
        const requiredDisclosuresOk = requirement.disclosures.every(
          (path) => getByPath(claims, path) !== undefined
        );
        if (!requiredDisclosuresOk) {
          deny("required_disclosure_missing");
        }
      }

      // True ZK predicate proofs (Groth16) travel in the direct_post.jwt response as an extension claim (`zk_proofs`).
      // This is validated here after we have the disclosed claim values (e.g. dob_commitment) and revocation state.
      if (decision === "ALLOW" && requirement) {
        if (requiresZk) {
          if (!input.requestHash) {
            deny("request_hash_required");
            allowObligations = false;
          } else if (!input.requestJwt) {
            deny("request_jwt_required");
            allowObligations = false;
          } else {
            const zk = await verifyRequiredZkPredicates({
              requiredPredicates: zkPredicates,
              zkProofs: input.zkProofs,
              requestHash: input.requestHash,
              nonce: input.nonce,
              audience: input.audience,
              requestJwt: input.requestJwt,
              claims,
              expectedVct: requirement.vct
            }).catch(() => ({ ok: false, reasons: ["zk_proof_invalid"] }));
            if (!zk.ok) {
              for (const r of zk.reasons) deny(r);
              allowObligations = false;
            }
          }
        }
      }

      if (decision === "ALLOW" && requirement) {
        const predicatesOk = requirement.predicates.every((predicate) => evaluatePredicate(predicate, claims));
        if (!predicatesOk) {
          deny("predicate_failed");
        }
      }

      if (decision === "ALLOW" && requirement) {
        const contextPredicates = requirement.context_predicates ?? [];
        const contextPredicatesOk = contextPredicates.every((predicate) =>
          evaluateContextPredicate(
            predicate,
            (input.context ?? requirements?.context ?? {}) as Record<string, unknown>,
            claims
          )
        );
        if (!contextPredicatesOk) {
          deny("space_context_mismatch");
        }
      }

      // Backward-compatible hardening for existing space policies that predate context predicates.
      if (
        decision === "ALLOW" &&
        requirement &&
        ["social.space.join", "social.space.post.create", "social.space.moderate"].includes(input.actionId) &&
        (requirement.context_predicates ?? []).length === 0
      ) {
        const requestSpaceId = getByPath(
          { context: (input.context ?? requirements?.context ?? {}) as Record<string, unknown> },
          "context.space_id"
        );
        const claimSpaceId = getByPath({ claims }, "claims.space_id");
        if (
          typeof requestSpaceId !== "string" ||
          requestSpaceId.length === 0 ||
          typeof claimSpaceId !== "string" ||
          claimSpaceId.length === 0 ||
          requestSpaceId !== claimSpaceId
        ) {
          deny("space_context_mismatch");
        }
      }

      if (decision === "ALLOW" && requirement?.revocation?.required !== false) {
        // Support revocation for both SD-JWT and DI+BBS via a shared `status.status_list` shape.
        const statusCheck = await verifyStatusListEntry(status as Record<string, unknown>);
        if (!statusCheck.valid) {
          deny(statusCheck.reason ?? "revoked");
        }
      }
    }

    if (challengeValid && allowObligations) {
      const obligationsResult = await executeObligations({
        actionId: input.actionId,
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
        action: input.actionId,
        decision
      });
      recordInvalidDecision(input.actionId, decision);
      return {
        decision,
        reasons,
        policyId: pinnedPolicyId ?? requirements?.policyId ?? undefined,
        policyVersion: pinnedPolicyVersion ?? requirements?.policyVersion ?? undefined,
        obligationExecutionId: obligationsResult.executionId,
        obligationsExecuted: obligationsResult.obligations
      };
    }

    metrics.incCounter("verify_decisions_total", {
      action: input.actionId,
      decision
    });
    recordInvalidDecision(input.actionId, decision);
    return {
      decision,
      reasons,
      policyId: pinnedPolicyId ?? requirements?.policyId ?? undefined,
      policyVersion: pinnedPolicyVersion ?? requirements?.policyVersion ?? undefined,
      obligationExecutionId: null,
      obligationsExecuted: []
    };
  } catch (error) {
    if (error instanceof CoreHttpError) throw error;
    log.error("verify.failed", { error });
    metrics.incCounter("verify_invalid_total", { action: input.actionId });
    if (error instanceof Error && error.message === "jwks_kid_not_found") {
      return { decision: "DENY", reasons: ["jwks_kid_not_found"] };
    }
    return { decision: "DENY", reasons: ["verification_failed"] };
  }
};

export const isCoreHttpError = (error: unknown): error is CoreHttpErrorShape =>
  Boolean(
    error &&
      typeof error === "object" &&
      typeof (error as { statusCode?: unknown }).statusCode === "number" &&
      typeof (error as { code?: unknown }).code === "string" &&
      typeof (error as { message?: unknown }).message === "string"
  );

export const __test__ = {
  dependencyFailureDeny,
  selectKey,
  resetIssuerKeyCache: () => {
    cachedKeys = null;
    cachedAt = 0;
  },
  resetPolicyVerifyKey: () => {
    cachedPolicyVerifyKey = null;
  }
};

