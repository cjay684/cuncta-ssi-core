import { FastifyInstance } from "fastify";
import { z } from "zod";
import { GatewayContext, sendProxyResponse } from "../server.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { makeErrorResponse } from "@cuncta/shared";

const ipAllowed = (ip: string | undefined, context: GatewayContext, limitPerMinute: number) => {
  const key = context.hashValue(ip ?? "unknown");
  return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
};

const resolveParamsSchema = z.object({
  did: z.string().min(8)
});

export const registerDidRoutes = (app: FastifyInstance, context: GatewayContext) => {
  if (!context.config.DID_SERVICE_BASE_URL) return;

  app.get(
    "/v1/dids/resolve/:did",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_DEFAULT_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ipAllowed(request.ip, context, context.config.RATE_LIMIT_IP_DEFAULT_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/dids/resolve/:did",
          kind: "ip"
        });
        return reply.code(429).send({
          error: "rate_limited",
          message: "IP rate limit exceeded"
        });
      }
      const params = resolveParamsSchema.parse(request.params);
      const url = new URL(
        `/v1/dids/resolve/${encodeURIComponent(params.did)}`,
        context.config.DID_SERVICE_BASE_URL
      );
      const response = await context.fetchImpl(url, { method: "GET" });
      if (!response.ok) {
        const requestId = (request as { requestId?: string }).requestId;
        log.warn("dids.resolve.proxy.failed", { requestId, status: response.status });
        return reply.code(503).send(
          makeErrorResponse("resolver_unavailable", "Resolver unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      reply.header("cache-control", "public, max-age=10");
      return sendProxyResponse(reply, response);
    }
  );
};
