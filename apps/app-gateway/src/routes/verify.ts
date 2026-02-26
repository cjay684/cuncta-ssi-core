import { FastifyInstance } from "fastify";
import { createHash } from "node:crypto";
import { GatewayContext, createServiceAuthHeader } from "../server.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { makeErrorResponse } from "@cuncta/shared";

const ipAllowed = (ip: string | undefined, context: GatewayContext, limitPerMinute: number) => {
  const key = context.hashValue(ip ?? "unknown");
  return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
};

export const registerVerifyRoutes = (app: FastifyInstance, context: GatewayContext) => {
  // Consumer surface is OID4VP (/oid4vp/*). Legacy endpoints are disabled when the gateway is
  // intentionally deployed as a public production service.
  const legacyVerifyEnabled =
    !(context.config.NODE_ENV === "production" && context.config.PUBLIC_SERVICE);

  if (
    context.config.VERIFIER_SERVICE_BASE_URL &&
    context.config.GATEWAY_SIGN_OID4VP_REQUEST &&
    context.config.APP_GATEWAY_PUBLIC_BASE_URL
  ) {
    app.get("/.well-known/jwks.json", async (_request, reply) => {
      try {
        const url = new URL("/.well-known/jwks.json", context.config.VERIFIER_SERVICE_BASE_URL);
        const response = await context.fetchImpl(url.toString(), { method: "GET" });
        if (!response.ok) {
          return reply.code(503).send(
            makeErrorResponse("internal_error", "JWKS unavailable", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const jwks = await response.json();
        return reply.send(jwks);
      } catch {
        return reply.code(503).send(
          makeErrorResponse("internal_error", "JWKS unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }
    });
  }

  if (legacyVerifyEnabled && context.config.VERIFIER_SERVICE_BASE_URL) {
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
        const contentLengthHeader = request.headers["content-length"];
        const contentLength = Number(
          Array.isArray(contentLengthHeader) ? contentLengthHeader[0] : contentLengthHeader
        );
        if (Number.isFinite(contentLength) && contentLength > context.config.BODY_LIMIT_BYTES) {
          return reply.code(413).send(
            makeErrorResponse("invalid_request", "Request body too large", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const url = new URL("/v1/verify", context.config.VERIFIER_SERVICE_BASE_URL);
        url.search = request.url.split("?")[1] ?? "";
        const requestId = (request as { requestId?: string }).requestId;
        const controller = new AbortController();
        const timeout = setTimeout(() => {
          controller.abort("verifier_proxy_timeout");
        }, context.config.VERIFIER_PROXY_TIMEOUT_MS);
        timeout.unref?.();
        let response: Response;
        try {
          response = await context.fetchImpl(url, {
            method: "POST",
            headers: {
              "content-type": "application/json"
            },
            body: JSON.stringify(request.body ?? {}),
            signal: controller.signal
          });
        } catch (error) {
          const detail = error instanceof Error ? error.message : "upstream_unavailable";
          log.warn("verify.proxy.unavailable", { requestId, detail });
          return reply.send({
            decision: "DENY",
            message: "Not allowed",
            requestId
          });
        } finally {
          clearTimeout(timeout);
        }
        const bodyText = await response.text();
        const responseHash = createHash("sha256").update(bodyText).digest("hex");
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

  if (legacyVerifyEnabled && context.config.POLICY_SERVICE_BASE_URL) {
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
        const incomingQuery = new URL(request.url, "http://localhost").searchParams;
        incomingQuery.forEach((value, key) => url.searchParams.set(key, value));
        if (
          !context.config.BREAK_GLASS_DISABLE_STRICT &&
          context.config.APP_GATEWAY_PUBLIC_BASE_URL &&
          !url.searchParams.has("verifier_origin")
        ) {
          url.searchParams.set(
            "verifier_origin",
            new URL(context.config.APP_GATEWAY_PUBLIC_BASE_URL).origin
          );
        }
        const response = await context.fetchImpl(url.toString(), { method: "GET" });
        if (!response.ok) {
          const requestId = (request as { requestId?: string }).requestId;
          let policyBody: { error?: string; message?: string } | null = null;
          try {
            const text = await response.text();
            policyBody = text ? (JSON.parse(text) as { error?: string; message?: string }) : null;
          } catch {
            policyBody = null;
          }
          if (
            policyBody &&
            typeof policyBody.error === "string" &&
            ["policy_integrity_failed", "catalog_integrity_failed", "policy_not_found", "invalid_request", "not_found"].includes(
              policyBody.error
            )
          ) {
            return reply.code(response.status).send(policyBody);
          }
          log.warn("requirements.proxy.failed", {
            requestId,
            status: response.status,
            policyError: policyBody?.error ?? "no_structured_body"
          });
          return reply.code(503).send(
            makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const policyPayload = (await response.json()) as {
          action?: string;
          policyId?: string;
          policyHash?: string;
          challenge?: { nonce?: string; audience?: string; expires_at?: string };
          [key: string]: unknown;
        };
        if (
          context.config.GATEWAY_SIGN_OID4VP_REQUEST &&
          context.config.VERIFIER_SERVICE_BASE_URL &&
          context.config.APP_GATEWAY_PUBLIC_BASE_URL &&
          policyPayload.challenge?.nonce &&
          policyPayload.challenge?.audience &&
          policyPayload.challenge?.expires_at &&
          policyPayload.policyHash &&
          policyPayload.action
        ) {
          const verifierSecret =
            context.config.SERVICE_JWT_SECRET_VERIFIER ??
            (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);
          if (verifierSecret) {
            try {
              const authHeader = await createServiceAuthHeader(context, {
                audience: context.config.SERVICE_JWT_AUDIENCE_VERIFIER ?? context.config.SERVICE_JWT_AUDIENCE,
                secret: verifierSecret,
                scope: ["verifier:request_sign"]
              });
              const signUrl = new URL("/v1/request/sign", context.config.VERIFIER_SERVICE_BASE_URL);
              const signRes = await context.fetchImpl(signUrl.toString(), {
                method: "POST",
                headers: {
                  "content-type": "application/json",
                  authorization: authHeader
                },
                body: JSON.stringify({
                  nonce: policyPayload.challenge.nonce,
                  audience: policyPayload.challenge.audience,
                  exp: Math.floor(Date.parse(policyPayload.challenge.expires_at) / 1000),
                  action_id: policyPayload.action,
                  policyHash: policyPayload.policyHash,
                  iss: context.config.APP_GATEWAY_PUBLIC_BASE_URL.replace(/\/$/, "")
                })
              });
              if (signRes.ok) {
                const signPayload = (await signRes.json()) as { request_jwt?: string };
                if (signPayload.request_jwt) {
                  policyPayload.request_jwt = signPayload.request_jwt;
                }
              }
            } catch (err) {
              const requestId = (request as { requestId?: string }).requestId;
              log.warn("requirements.proxy.sign_failed", {
                requestId,
                error: err instanceof Error ? err.message : "unknown"
              });
            }
          }
        }
        reply.header("cache-control", "no-store");
        return reply.send(policyPayload);
      }
    );
  }
};
