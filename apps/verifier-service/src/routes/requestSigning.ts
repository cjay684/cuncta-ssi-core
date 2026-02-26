import { FastifyInstance } from "fastify";
import { z } from "zod";
import { signOid4vpRequest, getVerifierJwks } from "../oid4vp/requestSigning.js";
import { config } from "../config.js";
import { requireServiceAuth } from "../auth.js";
import { makeErrorResponse } from "@cuncta/shared";

const signBodySchema = z.object({
  nonce: z.string().min(10),
  audience: z.string().min(3),
  exp: z.number().int().positive(),
  action_id: z.string().min(1),
  policyHash: z.string().min(8),
  iss: z.string().url(),
  state: z.string().min(6).optional(),
  response_uri: z.string().url().optional(),
  response_mode: z.string().min(1).optional(),
  response_type: z.string().min(1).optional(),
  client_id: z.string().min(1).optional(),
  client_id_scheme: z.string().min(1).optional(),
  presentation_definition: z.record(z.string(), z.unknown()).optional(),
  zk_context: z.record(z.string(), z.unknown()).optional()
});

export const registerRequestSigningRoutes = (app: FastifyInstance) => {
  app.get("/.well-known/jwks.json", async (_request, reply) => {
    if (!config.VERIFIER_SIGN_OID4VP_REQUEST) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "OID4VP request signing is disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    try {
      const jwks = await getVerifierJwks();
      return reply.send(jwks);
    } catch {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "JWKS unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
  });

  app.post("/v1/request/sign", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["verifier:request_sign"] });
    if (reply.sent) return;
    if (!config.VERIFIER_SIGN_OID4VP_REQUEST) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "OID4VP request signing is disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = signBodySchema.parse(request.body ?? {});
    try {
      const requestJwt = await signOid4vpRequest({
        nonce: body.nonce,
        audience: body.audience,
        exp: body.exp,
        action_id: body.action_id,
        policyHash: body.policyHash,
        iss: body.iss,
        state: body.state,
        response_uri: body.response_uri,
        response_mode: body.response_mode,
        response_type: body.response_type,
        client_id: body.client_id,
        client_id_scheme: body.client_id_scheme,
        presentation_definition: body.presentation_definition as Record<string, unknown> | undefined,
        zk_context: body.zk_context as Record<string, unknown> | undefined
      });
      return reply.send({ request_jwt: requestJwt });
    } catch (error) {
      const message = error instanceof Error ? error.message : "sign_failed";
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Request signing failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE ? { cause: message } : undefined
        })
      );
    }
  });
};
