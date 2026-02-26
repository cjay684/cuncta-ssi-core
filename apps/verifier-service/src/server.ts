import fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import { registerHealthRoutes } from "./routes/health.js";
import { registerPresentationRoutes } from "./routes/presentations.js";
import { registerVerifyRoutes } from "./routes/verify.js";
import { registerOid4vpRoutes } from "./routes/oid4vp.js";
import { registerRequestSigningRoutes } from "./routes/requestSigning.js";
import { loadZkStatementRegistry } from "@cuncta/zk-registry";
import { log } from "./log.js";
import { randomUUID } from "node:crypto";
import { metrics } from "./metrics.js";
import { makeErrorResponse } from "@cuncta/shared";
import { config } from "./config.js";
import { ensurePseudonymizerReady, ensurePseudonymizerConsistency } from "./pseudonymizer.js";
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
  if (config.NODE_ENV === "production" && config.PUBLIC_SERVICE) {
    log.error("public.service.not_allowed", { env: config.NODE_ENV });
    throw new Error("public_service_not_allowed");
  }
  if (config.NODE_ENV === "production" && !config.TRUST_PROXY) {
    log.error("trust.proxy.required", { env: config.NODE_ENV });
    throw new Error("trust_proxy_required_in_production");
  }
  if (config.NODE_ENV === "production" && config.ISSUER_JWKS) {
    log.error("issuer.jwks.disabled", { env: config.NODE_ENV });
    throw new Error("issuer_jwks_disabled_in_production");
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
    pluginTimeout: 60_000,
    bodyLimit: config.VERIFY_MAX_PRESENTATION_BYTES,
    trustProxy: config.TRUST_PROXY
  });
  ensurePseudonymizerReady();
  app.addHook("onReady", async () => {
    await ensurePseudonymizerConsistency();
    if (config.ALLOW_EXPERIMENTAL_ZK) {
      // Fail fast if artifact hashes do not match the registry (parameter poisoning hardening).
      await loadZkStatementRegistry();
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
    config.SERVICE_JWT_SECRET_VERIFIER ??
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

  app.addHook("preHandler", async (request, reply) => {
    if (!config.BACKUP_RESTORE_MODE) return;
    const path = request.url.split("?")[0];
    if (path === "/v1/verify" || path.startsWith("/v1/presentations")) {
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
    const statusCode = (error as { statusCode?: number }).statusCode;
    const errorCode = (error as { code?: string }).code;
    if (statusCode === 413 || errorCode === "FST_ERR_CTP_BODY_TOO_LARGE") {
      metrics.incCounter("verify_413_total");
      metrics.incCounter("verify_payload_too_large_total");
      return reply.code(413).send(
        makeErrorResponse("invalid_request", "Request body too large", {
          devMode: config.DEV_MODE
        })
      );
    }
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
  registerPresentationRoutes(app);
  registerVerifyRoutes(app);
  registerOid4vpRoutes(app);
  registerRequestSigningRoutes(app);

  return app;
};
