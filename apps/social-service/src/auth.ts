import { FastifyReply, FastifyRequest } from "fastify";
import { extractBearerToken, verifyServiceJwt, makeErrorResponse } from "@cuncta/shared";
import { config } from "./config.js";

export const requireServiceAuth = async (
  request: FastifyRequest,
  reply: FastifyReply,
  options?: { requiredScopes?: string[] }
) => {
  const serviceSecret =
    config.SERVICE_JWT_SECRET_SOCIAL ??
    (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined);
  if (!serviceSecret) {
    if (config.ALLOW_INSECURE_DEV_AUTH) {
      return;
    }
    await reply
      .code(503)
      .send(
        makeErrorResponse(
          "service_auth_not_configured",
          "Service authentication is not configured",
          { devMode: config.DEV_MODE }
        )
      );
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
    await verifyServiceJwt(token, {
      audience: config.SERVICE_JWT_AUDIENCE_SOCIAL ?? config.SERVICE_JWT_AUDIENCE,
      secret: serviceSecret,
      issuer: "app-gateway",
      subject: "app-gateway",
      requiredScopes: options?.requiredScopes
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
