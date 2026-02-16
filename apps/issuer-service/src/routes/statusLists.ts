import { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { log } from "../log.js";
import { getStatusList, revokeCredential } from "../issuer/issuance.js";
import { requireServiceAuth } from "../auth.js";
import { makeErrorResponse } from "@cuncta/shared";
import { config } from "../config.js";

const revokeSchema = z
  .object({
    eventId: z.string().min(3).optional(),
    credentialFingerprint: z.string().min(10).optional()
  })
  .refine((value) => value.eventId || value.credentialFingerprint, {
    message: "eventId_or_fingerprint_required"
  });

export const registerStatusListRoutes = (app: FastifyInstance) => {
  app.get("/status-lists/:listId", async (request, reply) => {
    reply.header("cache-control", "no-store");
    const params = z.object({ listId: z.string().min(1) }).parse(request.params);
    try {
      const { vc } = await getStatusList(params.listId);
      return reply.send(vc);
    } catch (error) {
      const requestId = (request as { requestId?: string }).requestId;
      log.error("status.list.get.failed", { requestId, error, listId: params.listId });
      return reply.code(404).send(
        makeErrorResponse("invalid_request", "Status list not found", {
          devMode: config.DEV_MODE
        })
      );
    }
  });

  const handleRevoke = async (request: FastifyRequest, reply: FastifyReply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["issuer:revoke"] });
    if (reply.sent) return;
    const body = revokeSchema.parse(request.body);
    try {
      const result = await revokeCredential({
        eventId: body.eventId,
        credentialFingerprint: body.credentialFingerprint
      });
      return reply.send({
        listId: result.listId,
        anchorPending: result.diagnostics?.anchorPending ?? true
      });
    } catch (error) {
      const requestId = (request as { requestId?: string }).requestId;
      log.error("credential.revoke.failed", { requestId, error });
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Revoke failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "Error" }
            : undefined
        })
      );
    }
  };

  app.post("/v1/credentials/revoke", async (request, reply) => {
    await handleRevoke(request, reply);
  });

  app.post("/v1/revoke", async (request, reply) => {
    await handleRevoke(request, reply);
  });
};
