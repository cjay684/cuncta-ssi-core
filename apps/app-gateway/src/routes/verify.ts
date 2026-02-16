import { FastifyInstance } from "fastify";
import { createHash } from "node:crypto";
import { GatewayContext, sendProxyResponse } from "../server.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { makeErrorResponse } from "@cuncta/shared";

const ipAllowed = (ip: string | undefined, context: GatewayContext, limitPerMinute: number) => {
  const key = context.hashValue(ip ?? "unknown");
  return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
};

export const registerVerifyRoutes = (app: FastifyInstance, context: GatewayContext) => {
  if (context.config.VERIFIER_SERVICE_BASE_URL) {
    app.post(
      "/v1/verify",
      {
        config: {
          rateLimit: {
            max: context.config.RATE_LIMIT_IP_VERIFY_PER_MIN,
            timeWindow: "1 minute"
          }
        }
      },
      async (request, reply) => {
        if (!ipAllowed(request.ip, context, context.config.RATE_LIMIT_IP_VERIFY_PER_MIN)) {
          metrics.incCounter("rate_limit_rejects_total", {
            route: "/v1/verify",
            kind: "ip"
          });
          return reply.code(429).send({
            error: "rate_limited",
            message: "IP rate limit exceeded"
          });
        }
        const url = new URL("/v1/verify", context.config.VERIFIER_SERVICE_BASE_URL);
        url.search = request.url.split("?")[1] ?? "";
        const response = await context.fetchImpl(url, {
          method: "POST",
          headers: {
            "content-type": "application/json"
          },
          body: JSON.stringify(request.body ?? {})
        });
        const bodyText = await response.text();
        const responseHash = createHash("sha256").update(bodyText).digest("hex");
        const requestId = (request as { requestId?: string }).requestId;
        if (!response.ok) {
          log.warn("verify.proxy.failed", { requestId, status: response.status, responseHash });
        } else {
          log.info("verify.proxy.ok", { requestId, status: response.status, responseHash });
        }

        let payload: { decision?: string; reasons?: string[] } | null = null;
        if (response.headers.get("content-type")?.includes("application/json")) {
          try {
            payload = JSON.parse(bodyText) as { decision?: string; reasons?: string[] };
          } catch {
            payload = null;
          }
        }
        const decision = payload?.decision === "ALLOW" ? "ALLOW" : "DENY";
        const normalized: { decision: "ALLOW" | "DENY"; message: string; requestId?: string } = {
          decision,
          message: decision === "ALLOW" ? "Allowed" : "Not allowed",
          requestId
        };
        if (context.config.GATEWAY_VERIFY_DEBUG_REASONS && payload?.reasons) {
          return reply.send({ ...normalized, reasons: payload.reasons });
        }
        return reply.send(normalized);
      }
    );
  }

  if (context.config.POLICY_SERVICE_BASE_URL) {
    app.get(
      "/v1/requirements",
      {
        config: {
          rateLimit: {
            max: context.config.RATE_LIMIT_IP_VERIFY_PER_MIN,
            timeWindow: "1 minute"
          }
        }
      },
      async (request, reply) => {
        if (!ipAllowed(request.ip, context, context.config.RATE_LIMIT_IP_VERIFY_PER_MIN)) {
          metrics.incCounter("rate_limit_rejects_total", {
            route: "/v1/requirements",
            kind: "ip"
          });
          return reply.code(429).send({
            error: "rate_limited",
            message: "IP rate limit exceeded"
          });
        }
        const req = request as { query?: { action?: string }; deviceHash?: string };
        const deviceId = request.headers["x-device-id"];
        if (typeof deviceId === "string" && deviceId.trim().length >= 8) {
          req.deviceHash = context.pseudonymizer.didToHash(deviceId.trim());
        } else if (context.config.REQUIRE_DEVICE_ID_FOR_REQUIREMENTS) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Missing device id", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        if (req.deviceHash) {
          const allowed = context.deviceQuotaMinute.consume(
            req.deviceHash,
            context.config.RATE_LIMIT_DEVICE_REQUIREMENTS_PER_MIN,
            60_000
          );
          if (!allowed) {
            metrics.incCounter("rate_limit_rejects_total", {
              route: "/v1/requirements",
              kind: "device_minute"
            });
            return reply.code(429).send(
              makeErrorResponse("rate_limited", "Device rate limit exceeded", {
                devMode: context.config.DEV_MODE
              })
            );
          }
        }
        const action = req.query?.action?.trim();
        if (!action) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Missing action", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        if (
          context.config.GATEWAY_REQUIREMENTS_ALLOWED_ACTIONS.length &&
          !context.config.GATEWAY_REQUIREMENTS_ALLOWED_ACTIONS.includes(action)
        ) {
          return reply.code(404).send(
            makeErrorResponse("not_found", "Action not allowed", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const url = new URL("/v1/requirements", context.config.POLICY_SERVICE_BASE_URL);
        url.search = request.url.split("?")[1] ?? "";
        const response = await context.fetchImpl(url, { method: "GET" });
        if (!response.ok) {
          const requestId = (request as { requestId?: string }).requestId;
          log.warn("requirements.proxy.failed", { requestId, status: response.status });
          return reply.code(503).send(
            makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        reply.header("cache-control", "no-store");
        return sendProxyResponse(reply, response);
      }
    );
  }
};
