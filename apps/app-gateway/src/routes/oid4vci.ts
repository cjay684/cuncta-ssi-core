import { FastifyInstance } from "fastify";
import { z } from "zod";
import { GatewayContext, createServiceAuthHeader, sendProxyResponse } from "../server.js";
import { makeErrorResponse } from "@cuncta/shared";

const querySchema = z.object({
  vct: z.string().min(3),
  format: z.enum(["dc+sd-jwt", "di+bbs"]).optional()
});

const auraChallengeQuerySchema = z.object({
  config_id: z.string().min(3)
});

const auraOfferBodySchema = z.object({
  credential_configuration_id: z.string().min(3),
  domain: z.string().min(1),
  space_id: z.string().uuid().optional(),
  subjectDid: z.string().min(3),
  offer_nonce: z.string().min(10),
  proof_jwt: z.string().min(10)
});

export const registerOid4vciRoutes = (app: FastifyInstance, context: GatewayContext) => {
  if (!context.config.ISSUER_SERVICE_BASE_URL) return;

  // Public helper to mint an OID4VCI credential offer for a given VCT.
  // This is intentionally thin: it does not accept PII and does not store any raw identifiers.
  app.get("/oid4vci/offer", async (request, reply) => {
    const query = querySchema.parse(request.query ?? {});
    const format = query.format ?? "dc+sd-jwt";
    if (!context.config.ALLOW_EXPERIMENTAL_ZK && format === "di+bbs") {
      return reply.code(404).send(
        makeErrorResponse("not_found", "Credential format disabled", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const allowlisted = context.config.GATEWAY_ALLOWED_VCTS.length
      ? context.config.GATEWAY_ALLOWED_VCTS.includes(query.vct)
      : true;
    if (!allowlisted) {
      return reply.code(403).send(
        makeErrorResponse("forbidden", "VCT not allowed", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const credentialConfigurationId =
      format === "dc+sd-jwt"
        ? query.vct === "age_credential_v1"
          ? "age_credential_v1"
          : `sdjwt:${query.vct}`
        : format === "di+bbs"
          ? `di-bbs:${query.vct}`
          : `sdjwt:${query.vct}`;
    const issuerSecret =
      context.config.SERVICE_JWT_SECRET_ISSUER ??
      (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);
    if (!issuerSecret) {
      return reply.code(503).send(
        makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const authHeader = await createServiceAuthHeader(context, {
      audience: context.config.SERVICE_JWT_AUDIENCE_ISSUER ?? context.config.SERVICE_JWT_AUDIENCE,
      secret: issuerSecret,
      scope: ["issuer:oid4vci_preauth"]
    });
    const url = new URL("/v1/internal/oid4vci/preauth", context.config.ISSUER_SERVICE_BASE_URL);
    const response = await context.fetchImpl(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: authHeader
      },
      body: JSON.stringify({ vct: credentialConfigurationId })
    });
    reply.header("cache-control", "no-store");
    return sendProxyResponse(reply, response);
  });

  // Aura capability issuance (portable entitlements) via standard OID4VCI.
  // This is a user-initiated portability surface: requires a holder-signed proof over a short-lived offer nonce.
  app.get("/oid4vci/aura/challenge", async (request, reply) => {
    const query = auraChallengeQuerySchema.parse(request.query ?? {});
    if (!query.config_id.startsWith("aura:")) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Invalid aura config", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const issuerSecret =
      context.config.SERVICE_JWT_SECRET_ISSUER ??
      (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);
    if (!issuerSecret) {
      return reply.code(503).send(
        makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const authHeader = await createServiceAuthHeader(context, {
      audience: context.config.SERVICE_JWT_AUDIENCE_ISSUER ?? context.config.SERVICE_JWT_AUDIENCE,
      secret: issuerSecret,
      scope: ["issuer:oid4vci_offer_challenge"]
    });
    const url = new URL("/v1/internal/oid4vci/offer-challenge", context.config.ISSUER_SERVICE_BASE_URL);
    const response = await context.fetchImpl(url, {
      method: "POST",
      headers: { authorization: authHeader }
    });
    reply.header("cache-control", "no-store");
    return sendProxyResponse(reply, response);
  });

  app.post("/oid4vci/aura/offer", async (request, reply) => {
    const body = auraOfferBodySchema.parse(request.body ?? {});
    if (!body.credential_configuration_id.startsWith("aura:")) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Invalid aura config", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    // Strict scope validation at the public surface (defense-in-depth; issuer repeats this fail-closed).
    // - marketplace/social: { domain: "marketplace"|"social" } (no extra keys)
    // - space:*: { space_id: "<uuid>" } -> derived domain "space:<uuid>"
    if (body.space_id) {
      const expected = `space:${body.space_id}`;
      if (body.domain !== expected) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Invalid capability scope", {
            devMode: context.config.DEV_MODE
          })
        );
      }
    } else {
      if (body.domain !== "marketplace" && body.domain !== "social") {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Invalid capability scope", {
            devMode: context.config.DEV_MODE
          })
        );
      }
    }
    const issuerSecret =
      context.config.SERVICE_JWT_SECRET_ISSUER ??
      (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);
    if (!issuerSecret) {
      return reply.code(503).send(
        makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const authHeader = await createServiceAuthHeader(context, {
      audience: context.config.SERVICE_JWT_AUDIENCE_ISSUER ?? context.config.SERVICE_JWT_AUDIENCE,
      secret: issuerSecret,
      scope: ["issuer:oid4vci_preauth"]
    });
    const url = new URL("/v1/internal/oid4vci/preauth/aura", context.config.ISSUER_SERVICE_BASE_URL);
    const response = await context.fetchImpl(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: authHeader
      },
      body: JSON.stringify(body)
    });
    reply.header("cache-control", "no-store");
    return sendProxyResponse(reply, response);
  });
};

