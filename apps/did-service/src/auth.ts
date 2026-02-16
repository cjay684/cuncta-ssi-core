import { FastifyReply, FastifyRequest } from "fastify";
import { extractBearerToken, verifyServiceJwt, makeErrorResponse } from "@cuncta/shared";
import { config } from "./config.js";
import { log } from "./log.js";

export const requireServiceAuth = async (
  request: FastifyRequest,
  reply: FastifyReply,
  options?: { requiredScopes?: string[] }
) => {
  const serviceSecret =
    config.SERVICE_JWT_SECRET_DID ??
    (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined);
  const nextSecret = config.SERVICE_JWT_SECRET_NEXT;
  if (!serviceSecret) {
    if (config.NODE_ENV === "production") {
      await reply
        .code(503)
        .send(
          makeErrorResponse(
            "service_auth_not_configured",
            "Service authentication is not configured",
            { devMode: config.DEV_MODE }
          )
        );
    }
    return;
  }
  const token = extractBearerToken(request.headers.authorization);
  if (!token) {
    await reply.code(401).send(
      makeErrorResponse("invalid_request", "Missing service token", {
        devMode: config.DEV_MODE
      })
    );
    return;
  }
  try {
    const audience = config.SERVICE_JWT_AUDIENCE_DID ?? config.SERVICE_JWT_AUDIENCE;
    let payload;
    try {
      payload = await verifyServiceJwt(token, {
        audience,
        secret: serviceSecret,
        issuer: "app-gateway",
        subject: "app-gateway",
        requiredScopes: options?.requiredScopes
      });
    } catch (error) {
      if (error instanceof Error && error.message === "jwt_missing_required_scope") {
        throw error;
      }
      if (nextSecret) {
        payload = await verifyServiceJwt(token, {
          audience,
          secret: nextSecret,
          issuer: "app-gateway",
          subject: "app-gateway",
          requiredScopes: options?.requiredScopes
        });
      } else {
        throw error;
      }
    }
    const scopeValue = payload.scope;
    const tokenScopes = Array.isArray(scopeValue)
      ? scopeValue.map(String)
      : typeof scopeValue === "string"
        ? scopeValue.split(" ").filter(Boolean)
        : [];
    const requestId = (request as { requestId?: string }).requestId;
    log.info("service.auth.ok", {
      requestId,
      caller: payload.iss ?? "unknown",
      scope: tokenScopes
    });
  } catch (error) {
    if (error instanceof Error && error.message === "jwt_missing_required_scope") {
      await reply.code(403).send(
        makeErrorResponse("service_auth_scope_missing", "Service token scope missing", {
          devMode: config.DEV_MODE
        })
      );
      return;
    }
    await reply.code(401).send(
      makeErrorResponse("invalid_request", "Invalid service token", {
        devMode: config.DEV_MODE
      })
    );
  }
};
