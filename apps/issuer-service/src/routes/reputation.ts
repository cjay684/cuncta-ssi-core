import { FastifyInstance } from "fastify";
import { z } from "zod";
import { log } from "../log.js";
import { recordEvent, recomputeReputation } from "../reputation/engine.js";
import { requireServiceAuth } from "../auth.js";
import { getDidHashes } from "../pseudonymizer.js";

const eventSchema = z.object({
  actor_pseudonym: z.string().min(3),
  counterparty_pseudonym: z.string().min(3),
  domain: z.string().min(1),
  event_type: z.string().min(1),
  timestamp: z.string().min(3),
  evidence_hash: z.string().optional()
});

export const registerReputationRoutes = (app: FastifyInstance) => {
  app.post("/v1/reputation/events", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["issuer:reputation_ingest"] });
    if (reply.sent) return;
    const body = eventSchema.parse(request.body);
    await recordEvent(body);
    log.info("reputation.event.recorded", { domain: body.domain, eventType: body.event_type });
    return reply.send({ ok: true });
  });

  app.post("/v1/reputation/recompute/:did", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["issuer:reputation_recompute"] });
    if (reply.sent) return;
    const params = z.object({ did: z.string().min(3) }).parse(request.params);
    const result = await recomputeReputation(params.did);
    log.info("reputation.recompute", {
      didHash: getDidHashes(params.did).primary,
      domainCount: result.domains.length
    });
    return reply.send(result);
  });
};
