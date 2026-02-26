import fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import formbody from "@fastify/formbody";
import { registerHealthRoutes } from "./routes/health.js";
import { registerIssuerRoutes } from "./routes/issuer.js";
import { registerStatusListRoutes } from "./routes/statusLists.js";
import { registerDevRoutes } from "./routes/dev.js";
import { registerCatalogRoutes } from "./routes/catalog.js";
import { registerReputationRoutes } from "./routes/reputation.js";
import { registerAuraRoutes } from "./routes/aura.js";
import { registerPrivacyRoutes } from "./routes/privacy.js";
import { registerKeyRoutes } from "./routes/keys.js";
import { registerAnchorRoutes } from "./routes/anchors.js";
import { log } from "./log.js";
import { randomUUID } from "node:crypto";
import { metrics } from "./metrics.js";
import { makeErrorResponse } from "@cuncta/shared";
import { config } from "./config.js";
import { ensurePseudonymizerReady, ensurePseudonymizerConsistency } from "./pseudonymizer.js";
import { getDb } from "./db.js";
import { ensureAuraRuleIntegrity } from "./aura/auraIntegrity.js";
import { registerSurfaceEnforcement } from "./surfaceEnforcement.js";
import net from "node:net";

const isLoopbackAddress = (value?: string) => {
  if (!value) return false;
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "localhost" || trimmed === "::1") return true;
  const mapped = trimmed.startsWith("::ffff:") ? trimmed.slice(7) : trimmed;
  const ipType = net.isIP(mapped);
  if (ipType === 4) {
    const [a] = mapped.split(".").map((part) => Number(part));
    return a === 127;
  }
  return false;
};

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
  ensurePseudonymizerReady();
  app.addHook("onReady", async () => {
    await ensurePseudonymizerConsistency();
    // Fail closed in production if any enabled capability rule violates the Aura capability contract.
    if (config.NODE_ENV === "production") {
      const db = await getDb();
      const rules = await db("aura_rules").where({ enabled: true });
      for (const rule of rules) {
        await ensureAuraRuleIntegrity(rule);
      }
      const duplicates = (await db("aura_rules")
        .where({ enabled: true })
        .select("domain", "output_vct")
        .count("rule_id as count")
        .groupBy("domain", "output_vct")
        .havingRaw("COUNT(rule_id) > 1")) as Array<{ domain: string; output_vct: string; count: string }>;
      if (duplicates.length > 0) {
        log.error("aura.rules.invariant_violated", { count: duplicates.length });
        throw new Error("aura_rules_invariant_violated");
      }
    }
  });
  if (config.ALLOW_INSECURE_DEV_AUTH) {
    if (config.NODE_ENV === "production") {
      log.error("service.auth.insecure_not_allowed", {
        env: config.NODE_ENV,
        bind: config.SERVICE_BIND_ADDRESS
      });
      throw new Error("insecure_dev_auth_not_allowed");
    }
    const localDevAllowed =
      config.NODE_ENV === "development" &&
      (config.LOCAL_DEV || isLoopbackAddress(config.SERVICE_BIND_ADDRESS));
    if (!localDevAllowed) {
      log.error("service.auth.insecure_not_allowed", {
        env: config.NODE_ENV,
        bind: config.SERVICE_BIND_ADDRESS
      });
      throw new Error("insecure_dev_auth_not_allowed");
    }
    log.warn("service.auth.insecure_enabled", { env: config.NODE_ENV });
  }
  const serviceSecret =
    config.SERVICE_JWT_SECRET_ISSUER ??
    (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined);
  if (!serviceSecret && !config.ALLOW_INSECURE_DEV_AUTH) {
    if (config.NODE_ENV === "production") {
      log.error("service.auth.missing", { env: config.NODE_ENV });
      throw new Error("service_auth_not_configured");
    } else {
      log.warn("service.auth.missing", { env: config.NODE_ENV });
    }
  }

  app.addHook("onRequest", async (request, reply) => {
    const incoming = request.headers["x-request-id"];
    const requestId = Array.isArray(incoming) ? incoming[0] : (incoming ?? randomUUID());
    (request as { requestId?: string }).requestId = requestId;
    reply.header("X-Request-Id", requestId);
    log.info("request", { requestId, method: request.method, url: request.url });
  });

  // Runtime public-surface enforcement (fail-closed) for customer-ready production deployments.
  // Only active in NODE_ENV=production with PUBLIC_SERVICE=true.
  registerSurfaceEnforcement(app, {
    config: {
      NODE_ENV: config.NODE_ENV,
      PUBLIC_SERVICE: config.PUBLIC_SERVICE,
      DEV_MODE: config.DEV_MODE,
      SERVICE_JWT_SECRET:
        config.SERVICE_JWT_SECRET_ISSUER ??
        (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined),
      SERVICE_JWT_AUDIENCE: config.SERVICE_JWT_AUDIENCE
    }
  });

  app.addHook("preHandler", async (request, reply) => {
    if (!config.BACKUP_RESTORE_MODE) return;
    const path = request.url.split("?")[0];
    const blocked =
      path === "/v1/issue" ||
      path === "/v1/admin/issue" ||
      path === "/token" ||
      path === "/credential" ||
      path.startsWith("/v1/privacy") ||
      path === "/v1/aura/claim" ||
      path === "/v1/credentials/revoke" ||
      path === "/v1/revoke";
    if (blocked) {
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
  // OID4VCI token endpoint needs `application/x-www-form-urlencoded`.
  app.register(formbody);

  registerHealthRoutes(app);
  registerIssuerRoutes(app);
  registerStatusListRoutes(app);
  registerCatalogRoutes(app);
  registerReputationRoutes(app);
  registerAuraRoutes(app);
  registerPrivacyRoutes(app);
  registerKeyRoutes(app);
  registerAnchorRoutes(app);
  registerDevRoutes(app);

  return app;
};
