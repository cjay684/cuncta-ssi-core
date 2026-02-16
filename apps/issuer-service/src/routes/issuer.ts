import { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import { log } from "../log.js";
import { issueCredential } from "../issuer/issuance.js";
import { ISSUER_DID, getIssuerJwksForVerifier } from "../issuer/identity.js";
import { TokenStore } from "../state/tokenStore.js";
import { makeErrorResponse } from "@cuncta/shared";
import { requireServiceAuth } from "../auth.js";

const tokenStore = new TokenStore(config.TOKEN_TTL_SECONDS);

const credentialRequestSchema = z.object({
  subjectDid: z.string().min(3),
  claims: z.record(z.string(), z.unknown()).default({}),
  vct: z.string().min(3),
  statusListId: z.string().min(1).optional(),
  format: z.string().optional()
});

const issueRequestSchema = z.object({
  subjectDid: z.string().min(3),
  vct: z.string().min(3),
  claims: z.record(z.string(), z.unknown()).default({})
});

const tokenRequestSchema = z.object({
  grant_type: z.string().min(3),
  "pre-authorized_code": z.string().optional()
});

const hasIssuerOverride = (body: unknown) => {
  if (!body || typeof body !== "object") return false;
  const record = body as Record<string, unknown>;
  return "issuerDid" in record || "issuer" in record || "iss" in record;
};

const parseTokenBody = (body: unknown) => {
  if (typeof body === "string") {
    const params = new URLSearchParams(body);
    return {
      grant_type: params.get("grant_type") ?? "",
      "pre-authorized_code": params.get("pre-authorized_code") ?? undefined
    };
  }
  if (body && typeof body === "object") {
    return body as Record<string, unknown>;
  }
  return {};
};

export const registerIssuerRoutes = (app: FastifyInstance) => {
  app.get("/v1/issuer", async (_request, reply) => {
    return reply.send({ issuerDid: ISSUER_DID });
  });

  app.get("/jwks.json", async (_request, reply) => {
    const jwks = await getIssuerJwksForVerifier();
    return reply.send(jwks);
  });

  app.get("/.well-known/openid-credential-issuer", async (_request, reply) => {
    return reply.send({
      credential_issuer: config.ISSUER_BASE_URL,
      token_endpoint: `${config.ISSUER_BASE_URL}/token`,
      credential_endpoint: `${config.ISSUER_BASE_URL}/credential`,
      grant_types_supported: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
      credentials_supported: [
        {
          id: "cuncta_sdjwt",
          format: "dc+sd-jwt",
          cryptographic_binding_methods_supported: ["did"],
          credential_signing_alg_values_supported: ["EdDSA"],
          types: ["VerifiableCredential"]
        }
      ]
    });
  });

  app.post("/token", async (request, reply) => {
    const body = tokenRequestSchema.parse(parseTokenBody(request.body));
    if (body.grant_type !== "urn:ietf:params:oauth:grant-type:pre-authorized_code") {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Unsupported grant type", {
          devMode: config.DEV_MODE
        })
      );
    }
    const accessToken = tokenStore.issue();
    return reply.send({
      access_token: accessToken,
      token_type: "bearer",
      expires_in: config.TOKEN_TTL_SECONDS
    });
  });

  app.post("/credential", async (request, reply) => {
    const requestId = (request as { requestId?: string }).requestId;
    const auth = request.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!tokenStore.isValid(token)) {
      return reply.code(401).send(
        makeErrorResponse("invalid_request", "Invalid token", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (hasIssuerOverride(request.body)) {
      return reply.code(400).send(
        makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
          devMode: config.DEV_MODE
        })
      );
    }

    const body = credentialRequestSchema.parse(request.body);
    if (body.format && body.format !== "dc+sd-jwt") {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Unsupported format", {
          devMode: config.DEV_MODE
        })
      );
    }

    log.info("issuer.credential.request", { requestId, vct: body.vct });
    let result;
    try {
      result = await issueCredential({
        subjectDid: body.subjectDid,
        claims: body.claims,
        vct: body.vct
      });
    } catch (error) {
      if (error instanceof Error && error.message === "catalog_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }

    return reply.send({ credential: result.credential });
  });

  app.post("/v1/issue", async (request, reply) => {
    if (config.NODE_ENV === "production" && !config.DEV_MODE) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "Route disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const requestId = (request as { requestId?: string }).requestId;
    if (hasIssuerOverride(request.body)) {
      return reply.code(400).send(
        makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = issueRequestSchema.parse(request.body);
    log.info("issuer.issue.request", { requestId, vct: body.vct });
    let result;
    try {
      result = await issueCredential({
        subjectDid: body.subjectDid,
        claims: body.claims,
        vct: body.vct
      });
    } catch (error) {
      if (error instanceof Error && error.message === "catalog_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
    return reply.send({
      credential: result.credential,
      eventId: result.eventId,
      credentialFingerprint: result.credentialFingerprint
    });
  });

  app.post("/v1/internal/issue", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["issuer:internal_issue"] });
    if (reply.sent) return;
    const requestId = (request as { requestId?: string }).requestId;
    if (hasIssuerOverride(request.body)) {
      return reply.code(400).send(
        makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = issueRequestSchema.parse(request.body);
    if (!config.ISSUER_INTERNAL_ALLOWED_VCTS.length) {
      return reply.code(403).send(
        makeErrorResponse("invalid_request", "Issuer allowlist not configured", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (!config.ISSUER_INTERNAL_ALLOWED_VCTS.includes(body.vct)) {
      return reply.code(403).send(
        makeErrorResponse("invalid_request", "VCT not allowed", {
          devMode: config.DEV_MODE
        })
      );
    }
    log.info("issuer.internal.issue.request", { requestId, vct: body.vct });
    let result;
    try {
      result = await issueCredential({
        subjectDid: body.subjectDid,
        claims: body.claims,
        vct: body.vct
      });
    } catch (error) {
      if (error instanceof Error && error.message === "catalog_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("catalog_integrity_failed", "Catalog integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
    return reply.send({
      credential: result.credential,
      eventId: result.eventId,
      credentialFingerprint: result.credentialFingerprint
    });
  });
};
