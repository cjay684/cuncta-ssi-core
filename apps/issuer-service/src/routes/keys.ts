import { FastifyInstance } from "fastify";
import { z } from "zod";
import { requireServiceAuth } from "../auth.js";
import { makeErrorResponse } from "@cuncta/shared";
import { config } from "../config.js";
import { rotateIssuerKey, revokeIssuerKey } from "../issuer/keyRing.js";

const revokeSchema = z.object({
  kid: z.string().min(1)
});

export const registerKeyRoutes = (app: FastifyInstance) => {
  app.post("/v1/admin/keys/rotate", async (request, reply) => {
    await requireServiceAuth(request, reply, { requireAdminScope: ["issuer:key_rotate"] });
    if (reply.sent) return;
    try {
      const result = await rotateIssuerKey();
      return reply.send({ ok: true, kid: result.kid });
    } catch (error) {
      const message = error instanceof Error ? error.message : "key_rotate_failed";
      if (message === "issuer_keys_private_storage_disabled") {
        return reply.code(503).send(
          makeErrorResponse("internal_error", "Issuer key rotation not configured", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
  });

  app.post("/v1/admin/keys/revoke", async (request, reply) => {
    await requireServiceAuth(request, reply, { requireAdminScope: ["issuer:key_revoke"] });
    if (reply.sent) return;
    const body = revokeSchema.parse(request.body);
    try {
      await revokeIssuerKey(body.kid);
      return reply.send({ ok: true });
    } catch (error) {
      if (error instanceof Error && error.message === "issuer_key_not_found") {
        return reply
          .code(404)
          .send(
            makeErrorResponse("invalid_request", "Key not found", { devMode: config.DEV_MODE })
          );
      }
      throw error;
    }
  });
};
