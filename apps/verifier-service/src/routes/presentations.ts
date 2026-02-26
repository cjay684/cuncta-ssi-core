import { FastifyInstance } from "fastify";
import { z } from "zod";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { PresentationRequestSchema, PresentationVerifySchema } from "@cuncta/shared";
import { verifySdJwtVc } from "@cuncta/sdjwt";
import { config } from "../config.js";
import { log } from "../log.js";
import { sha256Hex, sha256Base64Url } from "../crypto/sha256.js";
import { PresentationRequestStore, createNonce } from "../state/requestStore.js";
import policyMap from "../policy-map.json" with { type: "json" };
import { requireServiceAuth } from "../auth.js";
import { makeErrorResponse } from "@cuncta/shared";
import { verifyStatusListEntry } from "../statusList.js";
import { assertEd25519Jwk } from "../crypto/jwk.js";

const jwksSchema = z.object({
  keys: z.array(z.record(z.string(), z.unknown())).min(1)
});

let cachedKeys: Record<string, unknown>[] | null = null;
let cachedAt = 0;

const loadIssuerKeys = async () => {
  if (config.ISSUER_JWKS) {
    const parsed = jwksSchema.parse(JSON.parse(config.ISSUER_JWKS));
    return parsed.keys;
  }
  const now = Date.now();
  if (cachedKeys && now - cachedAt < 300_000) {
    return cachedKeys;
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
  const selected = !kid ? keys[0] : (keys.find((key) => key.kid === kid) ?? keys[0]);
  if (!selected) {
    throw new Error("jwks_missing");
  }
  return assertEd25519Jwk(selected as Record<string, unknown>, "issuer");
};

const requestStore = new PresentationRequestStore(5 * 60 * 1000);

const predicateSchema = z.object({
  path: z.string().min(1),
  op: z.enum(["eq", "neq", "gte", "lte", "in", "exists"]),
  value: z.unknown().optional()
});

const requirementSchema = z.object({
  vct: z.string().min(1),
  disclosures: z.array(z.string()).default([]),
  predicates: z.array(predicateSchema).default([]),
  revocation: z.object({ required: z.boolean() }).optional()
});

type Requirement = z.infer<typeof requirementSchema>;
type Predicate = z.infer<typeof predicateSchema>;

const getActionForPolicyId = (policyId: string) => {
  const map = policyMap as Record<string, string>;
  return map[policyId] ?? null;
};

const fetchRequirements = async (action: string): Promise<Requirement[]> => {
  const response = await fetch(
    `${config.POLICY_SERVICE_BASE_URL}/v1/requirements?action=${encodeURIComponent(action)}`
  );
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`policy_fetch_failed: ${text}`);
  }
  const payload = z
    .object({
      action: z.string(),
      requirements: z.array(requirementSchema)
    })
    .parse(await response.json());
  return payload.requirements;
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

const tierOrder: Record<string, number> = { bronze: 1, silver: 2, gold: 3 };

const evaluatePredicate = (predicate: Predicate, claims: Record<string, unknown>) => {
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
    case "gte": {
      if (typeof value === "number" && typeof predicate.value === "number") {
        return value >= predicate.value;
      }
      if (
        typeof value === "string" &&
        typeof predicate.value === "string" &&
        tierOrder[value] &&
        tierOrder[predicate.value]
      ) {
        return tierOrder[value] >= tierOrder[predicate.value];
      }
      return false;
    }
    case "lte": {
      if (typeof value === "number" && typeof predicate.value === "number") {
        return value <= predicate.value;
      }
      if (
        typeof value === "string" &&
        typeof predicate.value === "string" &&
        tierOrder[value] &&
        tierOrder[predicate.value]
      ) {
        return tierOrder[value] <= tierOrder[predicate.value];
      }
      return false;
    }
    default:
      return false;
  }
};

export const registerPresentationRoutes = (app: FastifyInstance) => {
  app.post("/v1/presentations/request", async (request, reply) => {
    const requestId = (request as { requestId?: string }).requestId;
    const body = PresentationRequestSchema.parse(request.body);
    const nonce = body.nonce ?? createNonce();
    const audience = body.audience ?? config.VERIFIER_AUDIENCE ?? config.ISSUER_SERVICE_BASE_URL;
    const action = getActionForPolicyId(body.policyId);
    if (!action) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Unknown policy id", {
          devMode: config.DEV_MODE
        })
      );
    }
    let requirements: Requirement[];
    try {
      requirements = await fetchRequirements(action);
    } catch (error) {
      log.error("presentation.request.policy_failed", { requestId, error, action });
      return reply.code(502).send(
        makeErrorResponse("internal_error", "Policy unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    const presentationDefinition = {
      id: action,
      query: {
        type: "dcql",
        credentials: requirements.map((req, index) => ({
          id: `cred_${index + 1}`,
          format: ["dc+sd-jwt"],
          vct: req.vct
        }))
      }
    };
    const entry = requestStore.create({
      policyId: body.policyId,
      nonce,
      audience,
      requirements
    });
    return reply.send({
      requestId: entry.requestId,
      presentationDefinition,
      nonce: entry.nonce,
      audience: entry.audience,
      requirements: entry.requirements
    });
  });

  app.post("/v1/presentations/verify", async (request, reply) => {
    await requireServiceAuth(request, reply, {
      requiredScopes: ["verifier:presentations_verify"]
    });
    if (reply.sent) return;
    const body = PresentationVerifySchema.parse(request.body);
    const requestId = (request as { requestId?: string }).requestId;
    const presentation =
      "presentation" in body && typeof body.presentation === "string"
        ? body.presentation
        : (body.sdJwtPresentation as string);
    const tokenHash = sha256Hex(presentation);
    log.info("presentation.verify", { requestId, tokenHash });

    try {
      const parts = presentation.split("~");
      const jwt = parts[0];
      const kbJwt = parts.at(-1) ?? "";
      if (!kbJwt) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "kb_jwt_missing" }
        });
      }
      const sdParts = parts.slice(0, -1);
      while (sdParts.length && sdParts.at(-1) === "") {
        sdParts.pop();
      }
      const sdJwtPresentation = `${sdParts.join("~")}~`;
      const entry = requestStore.get(body.requestId);
      if (!entry) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "request_expired" }
        });
      }
      const header = decodeProtectedHeader(jwt);
      const jwk = await selectKey(header.kid);
      const result = await verifySdJwtVc({
        token: sdJwtPresentation,
        jwks: { keys: [jwk as never] },
        allowLegacyTyp: config.SDJWT_COMPAT_LEGACY_TYP
      });

      const payload = result.payload;
      if (typeof payload.sub !== "string" || !payload.sub.startsWith("did:")) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "missing_subject", warnings: result.warnings }
        });
      }
      const status = payload.status as Record<string, unknown> | undefined;
      if (!status) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "missing_status", warnings: result.warnings }
        });
      }

      const vct = payload.vct;
      const matchingRequirement = entry.requirements.find((req) => req.vct === vct);
      if (!matchingRequirement) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "vct_mismatch" }
        });
      }
      const requiredClaimsOk = matchingRequirement.predicates.every((predicate) =>
        evaluatePredicate(predicate, result.claims)
      );
      if (!requiredClaimsOk) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "predicate_failed" }
        });
      }

      if (matchingRequirement.revocation?.required ?? true) {
        const statusCheck = await verifyStatusListEntry(status);
        if (!statusCheck.valid) {
          return reply.send({
            valid: false,
            claims: {},
            diagnostics: {
              reason: statusCheck.reason,
              warnings: result.warnings,
              sdjwt: result.diagnostics
            }
          });
        }
      }

      const kbHeader = decodeProtectedHeader(kbJwt);
      if (kbHeader.alg !== "EdDSA") {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "kb_jwt_invalid_alg" }
        });
      }
      const kbDecoded = decodeJwt(kbJwt) as Record<string, unknown>;
      const cnf = kbDecoded.cnf as { jwk?: Record<string, unknown> } | undefined;
      if (!cnf?.jwk) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "kb_jwt_missing_cnf" }
        });
      }
      const holderJwk = assertEd25519Jwk(cnf.jwk, "holder");
      const holderKey = await importJWK(holderJwk as never, "EdDSA");
      const kbPayload = await jwtVerify(kbJwt, holderKey);
      if (typeof kbPayload.payload.exp !== "number") {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "kb_jwt_missing_exp" }
        });
      }
      const kbAud = kbPayload.payload.aud;
      const kbNonce = kbPayload.payload.nonce;
      const audValid = Array.isArray(kbAud)
        ? kbAud.map(String).includes(entry.audience)
        : typeof kbAud === "string" && kbAud === entry.audience;
      if (!audValid || typeof kbNonce !== "string" || kbNonce !== entry.nonce) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: {
            reason: "aud_nonce_mismatch",
            warnings: result.warnings
          }
        });
      }

      const sdHash = kbPayload.payload.sd_hash;
      const expectedHash = sha256Base64Url(sdJwtPresentation);
      if (typeof sdHash !== "string" || sdHash !== expectedHash) {
        return reply.send({
          valid: false,
          claims: {},
          diagnostics: { reason: "sd_hash_mismatch" }
        });
      }

      return reply.send({
        valid: true,
        claims: result.claims,
        diagnostics: {
          warnings: result.warnings,
          sdjwt: result.diagnostics,
          integrityBoundary: "issuer"
        }
      });
    } catch (error) {
      log.error("presentation.verify.failed", { requestId, error });
      return reply.send({
        valid: false,
        claims: {},
        diagnostics: { reason: "verification_failed" }
      });
    }
  });
};
