import fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import websocket from "@fastify/websocket";
import { randomUUID } from "node:crypto";
import { config } from "./config.js";
import { log } from "./log.js";
import { metrics } from "./metrics.js";
import { registerHealthRoutes } from "./routes/health.js";
import { registerSocialRoutes } from "./routes/social.js";
import { makeErrorResponse } from "@cuncta/shared";

export const buildServer = () => {
  const app = fastify({
    logger: false,
    trustProxy: config.TRUST_PROXY,
    bodyLimit: config.BODY_LIMIT_BYTES
  });

  app.addHook("onRequest", async (request, reply) => {
    const incoming = request.headers["x-request-id"];
    const requestId = Array.isArray(incoming) ? incoming[0] : (incoming ?? randomUUID());
    (request as { requestId?: string }).requestId = requestId;
    reply.header("X-Request-Id", requestId);
  });

  app.addHook("preHandler", async (request, reply) => {
    if (!config.BACKUP_RESTORE_MODE) return;
    const path = request.url.split("?")[0];
    if (path.startsWith("/v1/social/")) {
      return reply.code(503).send(
        makeErrorResponse("maintenance_mode", "Service in backup restore mode", {
          devMode: config.DEV_MODE
        })
      );
    }
  });

  app.addHook("onResponse", async (request, reply) => {
    const route = request.routeOptions?.url ?? request.url.split("?")[0];
    metrics.incCounter("requests_total", {
      route,
      method: request.method,
      status: String(reply.statusCode)
    });
  });

  app.setErrorHandler((error, request, reply) => {
    const requestId = (request as { requestId?: string }).requestId;
    const err = error instanceof Error ? error : new Error("unknown_error");
    log.error("request.failed", { requestId, error: err.message });
    return reply.code(500).send(
      makeErrorResponse("internal_error", "Internal error", {
        devMode: config.DEV_MODE,
        debug: config.DEV_MODE ? { cause: err.message } : undefined
      })
    );
  });

  app.register(rateLimit, { max: 120, timeWindow: "1 minute" });
  app.register(websocket);

  registerHealthRoutes(app);
  registerSocialRoutes(app);

  return app;
};
