import { FastifyInstance } from "fastify";
import { z } from "zod";
import { makeErrorResponse } from "@cuncta/shared";
import { requireServiceAuth } from "../auth.js";
import { config } from "../config.js";
import { reconcileAnchors } from "../hedera/anchorReconciler.js";

const reconcileBodySchema = z.object({
  payloadHashes: z.array(z.string().min(8)).optional(),
  limit: z.number().int().min(1).max(50).optional(),
  force: z.boolean().optional()
});

export const registerAnchorRoutes = (app: FastifyInstance) => {
  app.post("/v1/admin/anchors/reconcile", async (request, reply) => {
    await requireServiceAuth(request, reply, { requireAdminScope: ["issuer:anchor_reconcile"] });
    if (reply.sent) return;
    if (!config.ANCHOR_RECONCILIATION_ENABLED) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Anchor reconciliation is disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = reconcileBodySchema.parse(request.body ?? {});
    try {
      const result = await reconcileAnchors({
        payloadHashes: body.payloadHashes,
        limit: body.limit,
        force: body.force
      });
      return reply.send(result);
    } catch (error) {
      const cause = error instanceof Error ? error.message : "error";
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Anchor reconciliation failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE ? { cause } : undefined
        })
      );
    }
  });
};
