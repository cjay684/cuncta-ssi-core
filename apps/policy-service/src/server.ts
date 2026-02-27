import fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import { registerHealthRoutes } from "./routes/health.js";
import { registerPolicyRoutes } from "./routes/policy.js";
import { log } from "./log.js";
import { randomUUID } from "node:crypto";
import { metrics } from "./metrics.js";
import { makeErrorResponse } from "@cuncta/shared";
import { config } from "./config.js";
import net from "node:net";
import { loadZkStatementRegistry } from "@cuncta/zk-registry";
import { getDb } from "./db.js";
import { PolicyLogicSchema } from "./policy/evaluate.js";

const isPrivateAddress = (value?: string) => {
  if (!value) return false;
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "localhost" || trimmed === "::1") return true;
  if (trimmed === "0.0.0.0" || trimmed === "::") return false;
  const mapped = trimmed.startsWith("::ffff:") ? trimmed.slice(7) : trimmed;
  const ipType = net.isIP(mapped);
  if (ipType === 4) {
    const [a, b] = mapped.split(".").map((part) => Number(part));
    if (a === 10 || a === 127) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  if (ipType === 6) {
    return mapped.startsWith("fc") || mapped.startsWith("fd");
  }
  return false;
};

export const buildServer = () => {
  if (config.NODE_ENV === "production" && config.PUBLIC_SERVICE) {
    log.error("public.service.not_allowed", { env: config.NODE_ENV });
    throw new Error("public_service_not_allowed");
  }
  if (config.NODE_ENV === "production" && !config.TRUST_PROXY) {
    log.error("trust.proxy.required", { env: config.NODE_ENV });
    throw new Error("trust_proxy_required_in_production");
  }
  if (config.NODE_ENV === "production" && !isPrivateAddress(config.SERVICE_BIND_ADDRESS)) {
    log.error("service.bind.public_not_allowed", {
      env: config.NODE_ENV,
      bind: config.SERVICE_BIND_ADDRESS
    });
    throw new Error("public_bind_not_allowed");
  }
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
    log.info("request", { requestId, method: request.method, url: request.url });
  });

  app.addHook("preHandler", async (request, reply) => {
    if (!config.BACKUP_RESTORE_MODE) return;
    const path = request.url.split("?")[0];
    if (path === "/v1/requirements" || path === "/v1/policy/evaluate") {
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
    if ((error as { validation?: unknown }).validation) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Invalid request", {
          details: err.message,
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE ? { cause: err.message } : undefined
        })
      );
    }
    log.error("request.failed", { requestId, error: err.message });
    return reply.code(500).send(
      makeErrorResponse("internal_error", "Internal error", {
        devMode: config.DEV_MODE,
        debug: config.DEV_MODE ? { cause: err.message } : undefined
      })
    );
  });

  app.register(rateLimit, { max: 120, timeWindow: "1 minute" });

  registerHealthRoutes(app);
  registerPolicyRoutes(app);

  app.addHook("onReady", async () => {
    // Fail fast (production posture only): ensure that enabled policies don't reference
    // unknown/unavailable ZK statements when the ZK track is enabled.
    if (config.NODE_ENV !== "production" || !config.ALLOW_EXPERIMENTAL_ZK) return;
    const registry = await loadZkStatementRegistry();
    const db = await getDb();
    const policies = (await db("policies")
      .select("policy_id", "logic")
      .where({ enabled: true })) as Array<{ policy_id: string; logic: unknown }>;
    for (const row of policies) {
      const logic = PolicyLogicSchema.safeParse(row.logic);
      if (!logic.success) continue;
      for (const req of logic.data.requirements) {
        for (const pred of req.zk_predicates ?? []) {
          const st = registry.get(pred.id);
          if (!st)
            throw new Error(`policy_references_unknown_zk_statement:${row.policy_id}:${pred.id}`);
          if (!st.available)
            throw new Error(
              `policy_references_unavailable_zk_statement:${row.policy_id}:${pred.id}`
            );
        }
      }
    }
  });

  return app;
};
