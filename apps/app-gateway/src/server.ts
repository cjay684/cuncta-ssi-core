import Fastify, { FastifyReply, FastifyRequest } from "fastify";
import rateLimit from "@fastify/rate-limit";
import { createHash, randomUUID } from "node:crypto";
import { createHmacSha256Pseudonymizer } from "@cuncta/shared";
import { Client, Transaction } from "@hashgraph/sdk";
import { config } from "./config.js";
import { log } from "./log.js";
import { QuotaStore } from "./abuse.js";
import { createServiceJwt } from "./serviceAuth.js";
import {
  commitSponsorBudgetReservation,
  reserveSponsorBudget,
  revertSponsorBudgetReservation
} from "./sponsorBudget.js";
import { metrics } from "./metrics.js";
import { registerHealthRoutes } from "./routes/health.js";
import { registerOnboardRoutes } from "./routes/onboard.js";
import { registerVerifyRoutes } from "./routes/verify.js";
import { registerMetricsRoutes } from "./routes/metrics.js";
import { registerCapabilitiesRoutes } from "./routes/capabilities.js";
import { registerDidRoutes } from "./routes/dids.js";
import { registerSocialRoutes } from "./routes/social.js";

export type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

export type SubmitUserPaysTransaction = (input: {
  network: "testnet" | "previewnet" | "mainnet";
  signedTransactionBytes: Uint8Array;
}) => Promise<{ transactionId: string; status?: string }>;

export type GatewayContext = {
  config: typeof config;
  fetchImpl: FetchLike;
  deviceQuotaDaily: QuotaStore;
  deviceQuotaMinute: QuotaStore;
  ipQuotaMinute: QuotaStore;
  pseudonymizer: ReturnType<typeof createHmacSha256Pseudonymizer>;
  createServiceJwt: typeof createServiceJwt;
  reserveSponsorBudget: typeof reserveSponsorBudget;
  commitSponsorBudgetReservation: typeof commitSponsorBudgetReservation;
  revertSponsorBudgetReservation: typeof revertSponsorBudgetReservation;
  hashValue: (value: string) => string;
  submitUserPaysTransaction: SubmitUserPaysTransaction;
};

export type GatewayRequest = FastifyRequest & {
  requestId?: string;
  deviceHash?: string;
};

const hashValue = (value: string) => createHash("sha256").update(value).digest("hex");

export const buildServer = (input?: {
  configOverride?: typeof config;
  fetchImpl?: FetchLike;
  reserveSponsorBudget?: typeof reserveSponsorBudget;
  commitSponsorBudgetReservation?: typeof commitSponsorBudgetReservation;
  revertSponsorBudgetReservation?: typeof revertSponsorBudgetReservation;
  submitUserPaysTransaction?: SubmitUserPaysTransaction;
}) => {
  const activeConfig = input?.configOverride ?? config;
  const fetchImpl = input?.fetchImpl ?? fetch;
  const reserveSponsorBudgetImpl = input?.reserveSponsorBudget ?? reserveSponsorBudget;
  const commitSponsorBudgetReservationImpl =
    input?.commitSponsorBudgetReservation ?? commitSponsorBudgetReservation;
  const revertSponsorBudgetReservationImpl =
    input?.revertSponsorBudgetReservation ?? revertSponsorBudgetReservation;
  const submitUserPaysTransactionImpl =
    input?.submitUserPaysTransaction ??
    (async ({ network, signedTransactionBytes }) => {
      const client = Client.forName(network);
      const transaction = Transaction.fromBytes(signedTransactionBytes);
      const response = await transaction.execute(client);
      const receipt = await response.getReceipt(client);
      if (typeof client.close === "function") {
        client.close();
      }
      return {
        transactionId: response.transactionId?.toString() ?? "",
        status: receipt.status?.toString()
      };
    });
  if (activeConfig.NODE_ENV === "production" && !activeConfig.TRUST_PROXY) {
    log.error("trust.proxy.required", { env: activeConfig.NODE_ENV });
    throw new Error("trust_proxy_required_in_production");
  }
  if (activeConfig.GATEWAY_VERIFY_DEBUG_REASONS) {
    log.warn("gateway.verify.debug_reasons_enabled", { env: activeConfig.NODE_ENV });
    if (activeConfig.NODE_ENV === "production") {
      log.error("gateway.verify.debug_reasons_production", { env: activeConfig.NODE_ENV });
      throw new Error("gateway_verify_debug_reasons_disabled");
    }
  }
  log.info("gateway.routes.config", {
    contractE2eEnabled: activeConfig.CONTRACT_E2E_ENABLED,
    revokeRouteEnabled: activeConfig.CONTRACT_E2E_ENABLED,
    requirementsAllowlist: activeConfig.GATEWAY_REQUIREMENTS_ALLOWED_ACTIONS.length > 0,
    requirementsAllowlistCount: activeConfig.GATEWAY_REQUIREMENTS_ALLOWED_ACTIONS.length,
    contractE2eIpAllowlistCount: activeConfig.CONTRACT_E2E_IP_ALLOWLIST.length,
    requirementsRequireDeviceId: activeConfig.REQUIRE_DEVICE_ID_FOR_REQUIREMENTS
  });
  const app = Fastify({
    logger: false,
    bodyLimit: activeConfig.BODY_LIMIT_BYTES,
    trustProxy: activeConfig.TRUST_PROXY
  });

  app.addHook("onRequest", async (request) => {
    const req = request as GatewayRequest;
    req.requestId = randomUUID();
  });

  app.addHook("preHandler", async (request, reply) => {
    if (!activeConfig.BACKUP_RESTORE_MODE) return;
    const path = request.url.split("?")[0];
    if (path.startsWith("/v1/onboard") || path === "/v1/verify") {
      return reply.code(503).send({
        error: "maintenance_mode",
        message: "Service in backup restore mode"
      });
    }
  });

  app.addHook("onResponse", async (request, reply) => {
    const req = request as GatewayRequest;
    const ipHash = request.ip ? hashValue(request.ip) : "unknown";
    log.info("request.complete", {
      requestId: req.requestId,
      method: request.method,
      route: request.routeOptions?.url ?? request.url,
      status: reply.statusCode,
      ipHash,
      device: req.deviceHash ? req.deviceHash.slice(0, 12) : undefined
    });
    const route = request.routeOptions?.url ?? request.url.split("?")[0];
    metrics.incCounter("requests_total", {
      route,
      method: request.method,
      status: String(reply.statusCode)
    });
  });

  app.setErrorHandler((error, request, reply) => {
    const req = request as GatewayRequest;
    const err = error instanceof Error ? error : new Error("unknown_error");
    log.error("request.failed", { requestId: req.requestId, error: err.message });
    const statusCode = (error as { statusCode?: number }).statusCode;
    const errorCode = (error as { code?: string }).code;
    if (statusCode === 413 || errorCode === "FST_ERR_CTP_BODY_TOO_LARGE") {
      return reply.code(413).send({ error: "invalid_request", message: "Request body too large" });
    }
    reply.code(500).send({ error: "internal_error", message: "Unexpected error" });
  });

  app.register(rateLimit, {
    global: false,
    keyGenerator: (request) => request.ip,
    timeWindow: "1 minute",
    max: activeConfig.RATE_LIMIT_IP_DEFAULT_PER_MIN
  });

  const context: GatewayContext = {
    config: activeConfig,
    fetchImpl,
    deviceQuotaDaily: new QuotaStore(),
    deviceQuotaMinute: new QuotaStore(),
    ipQuotaMinute: new QuotaStore(),
    pseudonymizer: createHmacSha256Pseudonymizer({ pepper: activeConfig.PSEUDONYMIZER_PEPPER }),
    createServiceJwt,
    reserveSponsorBudget: reserveSponsorBudgetImpl,
    commitSponsorBudgetReservation: commitSponsorBudgetReservationImpl,
    revertSponsorBudgetReservation: revertSponsorBudgetReservationImpl,
    hashValue,
    submitUserPaysTransaction: submitUserPaysTransactionImpl
  };

  registerHealthRoutes(app);
  registerMetricsRoutes(app);
  registerCapabilitiesRoutes(app, context);
  registerOnboardRoutes(app, context);
  registerVerifyRoutes(app, context);
  registerDidRoutes(app, context);
  registerSocialRoutes(app, context);

  return app;
};

export const sendProxyResponse = async (reply: FastifyReply, response: Response) => {
  const contentType = response.headers.get("content-type") ?? "";
  reply.code(response.status);
  if (contentType.includes("application/json")) {
    return reply.send(await response.json());
  }
  return reply.send(await response.text());
};

export const requireDeviceHash = (request: GatewayRequest, context: GatewayContext) => {
  const deviceId = request.headers["x-device-id"];
  if (typeof deviceId !== "string" || deviceId.trim().length < 8) {
    return null;
  }
  const hash = context.pseudonymizer.didToHash(deviceId.trim());
  request.deviceHash = hash;
  return hash;
};

export const createServiceAuthHeader = async (
  context: GatewayContext,
  input: { audience: string; secret: string; scope: string[] | string }
) => {
  const token = await context.createServiceJwt({
    audience: input.audience,
    secret: input.secret,
    scope: input.scope,
    ttlSeconds: context.config.SERVICE_JWT_TTL_SECONDS
  });
  return `Bearer ${token}`;
};
