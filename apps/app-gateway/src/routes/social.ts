import { FastifyInstance } from "fastify";
import { GatewayContext, createServiceAuthHeader, sendProxyResponse } from "../server.js";
import { makeErrorResponse } from "@cuncta/shared";

const getSocialSecret = (context: GatewayContext) =>
  context.config.SERVICE_JWT_SECRET_SOCIAL ??
  (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);

const REALTIME_PROTOCOL_NAME = "cuncta-rt";
const REALTIME_PROTOCOL_TOKEN_PREFIX = `${REALTIME_PROTOCOL_NAME}.token.`;

export const parseWebsocketProtocolHeader = (header: string | string[] | undefined) => {
  if (!header) return [] as string[];
  const value = Array.isArray(header) ? header.join(",") : header;
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
};

export const extractRealtimeToken = (input: {
  protocols: string[];
  queryToken: string | null;
  allowQueryToken: boolean;
}) => {
  const tokenProtocol = input.protocols.find((entry) => entry.startsWith(REALTIME_PROTOCOL_TOKEN_PREFIX));
  if (tokenProtocol) {
    const token = tokenProtocol.slice(REALTIME_PROTOCOL_TOKEN_PREFIX.length).trim();
    if (!token) {
      return { ok: false as const, code: "invalid_request", tokenSource: "subprotocol" as const };
    }
    return { ok: true as const, permissionToken: token, tokenSource: "subprotocol" as const };
  }
  if (input.queryToken) {
    if (!input.allowQueryToken) {
      return { ok: false as const, code: "invalid_request", tokenSource: "query" as const };
    }
    return { ok: true as const, permissionToken: input.queryToken, tokenSource: "query" as const };
  }
  return { ok: false as const, code: "invalid_request", tokenSource: "missing" as const };
};

const proxyToSocial = async (
  context: GatewayContext,
  input: {
    method: "GET" | "POST";
    path: string;
    query?: string;
    body?: unknown;
    timeoutMs?: number;
  }
) => {
  const secret = getSocialSecret(context);
  if (!secret) {
    throw new Error("social_service_auth_unavailable");
  }
  if (!context.config.SOCIAL_SERVICE_BASE_URL) {
    throw new Error("social_service_unavailable");
  }
  const authHeader = await createServiceAuthHeader(context, {
    audience: context.config.SERVICE_JWT_AUDIENCE_SOCIAL ?? context.config.SERVICE_JWT_AUDIENCE,
    secret,
    scope: ["social:proxy"]
  });
  const url = new URL(input.path, context.config.SOCIAL_SERVICE_BASE_URL);
  if (input.query) {
    url.search = input.query;
  }
  const controller = new AbortController();
  const timeoutMs = input.timeoutMs ?? 0;
  const timeout =
    timeoutMs > 0
      ? setTimeout(() => {
          controller.abort("social_proxy_timeout");
        }, timeoutMs)
      : null;
  timeout?.unref?.();
  try {
    return await context.fetchImpl(url, {
      method: input.method,
      headers: {
        Authorization: authHeader,
        ...(input.method === "POST" ? { "content-type": "application/json" } : {})
      },
      ...(input.method === "POST" ? { body: JSON.stringify(input.body ?? {}) } : {}),
      signal: controller.signal
    });
  } catch (error) {
    if (controller.signal.aborted && controller.signal.reason === "social_proxy_timeout") {
      throw new Error("social_proxy_timeout");
    }
    throw error;
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
};

const sendProxyResponseWithFeeQuote = async (
  reply: Parameters<typeof sendProxyResponse>[0],
  response: Response,
  input: {
    feeQuote: ReturnType<GatewayContext["getFeeQuoteForPurpose"]>;
    feeScheduleFingerprint: string;
    paymentRequest: ReturnType<GatewayContext["getPaymentRequest"]>;
  }
) => {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return sendProxyResponse(reply, response);
  }
  const raw = await response.text();
  let payload: Record<string, unknown> | null = null;
  try {
    const parsed = JSON.parse(raw) as unknown;
    payload = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    payload = null;
  }
  if (!payload || Array.isArray(payload)) {
    return reply.code(response.status).send(raw);
  }
  return reply.code(response.status).send({
    ...payload,
    feeQuote: input.feeQuote,
    feeQuoteFingerprint: input.feeQuote?.quoteFingerprint ?? null,
    feeScheduleFingerprint: input.feeScheduleFingerprint,
    paymentRequest: input.paymentRequest,
    paymentRequestFingerprint: input.paymentRequest?.paymentRequestFingerprint ?? null
  });
};

export const registerSocialRoutes = (app: FastifyInstance, context: GatewayContext) => {
  if (!context.config.SOCIAL_SERVICE_BASE_URL) {
    return;
  }

  app.get("/v1/social/requirements", async (request, reply) => {
    if (!context.config.POLICY_SERVICE_BASE_URL) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const req = request as { query?: { action?: string } };
    const action = req.query?.action?.trim();
    if (!action) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Missing action", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const queryString = request.url.includes("?")
      ? request.url.slice(request.url.indexOf("?"))
      : "";
    const response = await context.fetchImpl(
      `${context.config.POLICY_SERVICE_BASE_URL}/v1/requirements${queryString}`,
      { method: "GET" }
    );
    if (!response.ok) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const payload = (await response.json().catch(() => null)) as {
      requirements?: Array<{ vct: string; disclosures?: string[] }>;
    } | null;
    if (!payload) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const requirementLabels: Record<string, string> = {
      "cuncta.social.account_active": "Active social account",
      "cuncta.social.can_post": "Ability to post",
      "cuncta.social.can_comment": "Ability to reply",
      "cuncta.social.trusted_creator": "Trusted creator capability",
      "cuncta.social.space.member": "Space member capability",
      "cuncta.social.space.poster": "Space poster capability",
      "cuncta.social.space.moderator": "Space moderator capability",
      "cuncta.social.space.steward": "Space steward capability",
      "cuncta.media.emoji_creator": "Emoji creator capability",
      "cuncta.media.soundpack_creator": "Soundpack creator capability",
      "cuncta.sync.watch_host": "Watch host capability",
      "cuncta.presence.mode_access": "Presence mode access capability",
      "cuncta.sync.scroll_host": "Scroll host capability",
      "cuncta.sync.listen_host": "Listen host capability",
      "cuncta.sync.session_participant": "Sync session participant capability",
      "cuncta.sync.huddle_host": "Hangout host capability",
      "cuncta.social.ritual_creator": "Ritual creator capability"
    };
    return reply.send({
      ...payload,
      requirements: (payload.requirements ?? []).map((entry) => ({
        ...entry,
        label: requirementLabels[entry.vct] ?? entry.vct
      }))
    });
  });

  app.post("/v1/media/upload/request", async (request, reply) => {
    try {
      const feeQuote = context.getFeeQuoteForPurpose("media.upload.request");
      const paymentRequest = context.getPaymentRequest({
        feeQuote,
        purposeScope: "media.upload.request"
      });
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/media/upload/request",
        body: request.body ?? {}
      });
      return sendProxyResponseWithFeeQuote(reply, response, {
        feeQuote,
        feeScheduleFingerprint: context.feeScheduleFingerprint,
        paymentRequest
      });
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/media/upload/complete", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/media/upload/complete",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/media/view/request", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/media/view/request",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/realtime/token", async (request, reply) => {
    try {
      const feeQuote = context.getFeeQuoteForPurpose("realtime.token");
      const paymentRequest = context.getPaymentRequest({
        feeQuote,
        purposeScope: "realtime.token"
      });
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/realtime/token",
        body: request.body ?? {}
      });
      return sendProxyResponseWithFeeQuote(reply, response, {
        feeQuote,
        feeScheduleFingerprint: context.feeScheduleFingerprint,
        paymentRequest
      });
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/realtime/events", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/realtime/events",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : "",
        timeoutMs: context.config.REALTIME_SOCIAL_FETCH_TIMEOUT_MS
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/realtime/connect", { websocket: true }, async (connection, request) => {
    try {
      const reqUrl = new URL(request.url, "http://localhost");
      const offeredProtocols = parseWebsocketProtocolHeader(
        request.headers["sec-websocket-protocol"] as string | string[] | undefined
      );
      const extracted = extractRealtimeToken({
        protocols: offeredProtocols,
        queryToken: reqUrl.searchParams.get("permission_token")?.trim() ?? null,
        allowQueryToken: context.config.REALTIME_ALLOW_QUERY_TOKEN
      });
      if (!extracted.ok) {
        connection.socket.send(JSON.stringify({ type: "error", code: "invalid_request" }));
        connection.socket.close(1008, "invalid_request");
        return;
      }
      const permissionToken = extracted.permissionToken;
      let closed = false;
      let after: string | null = reqUrl.searchParams.get("after")?.trim() ?? null;
      if (after && !/^\d+$/.test(after)) {
        connection.socket.send(JSON.stringify({ type: "error", code: "invalid_request" }));
        connection.socket.close(1008, "invalid_request");
        return;
      }
      const closeWithRealtimeError = (code: string, reason: string) => {
        if (closed) return;
        connection.socket.send(JSON.stringify({ type: "error", code }));
        connection.socket.close(1011, reason);
        closed = true;
      };
      const pushEvents = async () => {
        const query = new URLSearchParams();
        query.set("permissionToken", permissionToken);
        if (after) {
          query.set("after", after);
        }
        query.set("limit", "200");
        const response = await proxyToSocial(context, {
          method: "GET",
          path: "/v1/social/realtime/events",
          query: `?${query.toString()}`,
          timeoutMs: context.config.REALTIME_SOCIAL_FETCH_TIMEOUT_MS
        });
        if (!response.ok) {
          throw new Error(`realtime_events_fetch_failed:${response.status}`);
        }
        const payload = (await response.json().catch(() => null)) as
          | { events?: Array<{ createdAt?: string; cursor?: string | null }>; nextCursor?: string | null }
          | null;
        const events = payload?.events ?? [];
        for (const event of events) {
          if (event.cursor && /^\d+$/.test(event.cursor)) {
            after = event.cursor;
          }
        }
        if (payload?.nextCursor && /^\d+$/.test(payload.nextCursor)) {
          after = payload.nextCursor;
        }
        if (events.length > 0) {
          connection.socket.send(JSON.stringify({ type: "events", events }));
        }
      };
      const loop = async () => {
        while (!closed) {
          try {
            await pushEvents();
          } catch (error) {
            const message = error instanceof Error ? error.message : "realtime_events_fetch_failed";
            if (message === "social_proxy_timeout") {
              closeWithRealtimeError("upstream_timeout", "upstream_timeout");
            } else {
              closeWithRealtimeError("upstream_unavailable", "upstream_unavailable");
            }
            return;
          }
          await new Promise((resolve) => setTimeout(resolve, context.config.REALTIME_WS_POLL_MS));
        }
      };
      let liveLoopStarted = false;
      const startLiveLoop = () => {
        if (liveLoopStarted || closed) return;
        liveLoopStarted = true;
        void loop();
      };
      const liveStartDelay = setTimeout(() => {
        startLiveLoop();
      }, 50);
      liveStartDelay.unref?.();
      connection.socket.on("message", async (raw: Buffer) => {
        try {
          const data = JSON.parse(String(raw ?? "{}")) as {
            type?: string;
            eventType?: string;
            payload?: unknown;
            after?: string | number | null;
            channels?: string[];
          };
          if (data.type === "hello") {
            clearTimeout(liveStartDelay);
            const requestedAfter =
              data.after === null || data.after === undefined ? null : String(data.after).trim();
            if (requestedAfter && !/^\d+$/.test(requestedAfter)) {
              closeWithRealtimeError("invalid_request", "invalid_request");
              return;
            }
            after = requestedAfter;
            try {
              await pushEvents();
            } catch (error) {
              const message = error instanceof Error ? error.message : "realtime_events_fetch_failed";
              if (message === "social_proxy_timeout") {
                closeWithRealtimeError("upstream_timeout", "upstream_timeout");
              } else {
                closeWithRealtimeError("upstream_unavailable", "upstream_unavailable");
              }
              return;
            }
            connection.socket.send(
              JSON.stringify({
                type: "hello_ack",
                server_time: new Date().toISOString(),
                resume_from: requestedAfter
              })
            );
            startLiveLoop();
            return;
          }
          if (data.type !== "publish") {
            startLiveLoop();
            return;
          }
          if (!data.eventType) return;
          const publishResponse = await proxyToSocial(context, {
            method: "POST",
            path: "/v1/social/realtime/publish",
            body: {
              permissionToken,
              eventType: data.eventType,
              payload: data.payload ?? {}
            },
            timeoutMs: context.config.REALTIME_SOCIAL_FETCH_TIMEOUT_MS
          });
          if (!publishResponse.ok) {
            closeWithRealtimeError("publish_failed", "publish_failed");
            return;
          }
          startLiveLoop();
        } catch {
          closeWithRealtimeError("invalid_message", "invalid_message");
        }
      });
      connection.socket.on("close", () => {
        closed = true;
        clearTimeout(liveStartDelay);
      });
      connection.socket.on("error", () => {
        closed = true;
        clearTimeout(liveStartDelay);
      });
      connection.socket.send(
        JSON.stringify({
          type: "ready",
          protocol: offeredProtocols.includes(REALTIME_PROTOCOL_NAME) ? REALTIME_PROTOCOL_NAME : null,
          token_source: extracted.tokenSource
        })
      );
    } catch {
      connection.socket.close(1011, "internal_error");
    }
  });

  app.post("/v1/social/profile/create", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/profile/create",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/post", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/post",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/reply", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/reply",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/follow", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/follow",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/report", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/report",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/feed", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/feed",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/feed/flow", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/feed/flow",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/post/:postId/explain", async (request, reply) => {
    try {
      const params = request.params as { postId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/post/${encodeURIComponent(params.postId)}/explain`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/space/create", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/space/create",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/space/join", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/space/join",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/space/post", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/space/post",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/space/moderate", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "POST",
        path: "/v1/social/space/moderate",
        body: request.body ?? {}
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/space/feed", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/space/feed",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/space/flow", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/space/flow",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/spaces", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/spaces",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/spaces/:spaceId", async (request, reply) => {
    try {
      const params = request.params as { spaceId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/spaces/:spaceId/rules", async (request, reply) => {
    try {
      const params = request.params as { spaceId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/rules`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/spaces/:spaceId/governance", async (request, reply) => {
    try {
      const params = request.params as { spaceId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/governance`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/spaces/:spaceId/moderation/cases", async (request, reply) => {
    try {
      const params = request.params as { spaceId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/moderation/cases`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post(
    "/v1/social/spaces/:spaceId/moderation/cases/:caseId/resolve",
    async (request, reply) => {
      try {
        const params = request.params as { spaceId: string; caseId: string };
        const response = await proxyToSocial(context, {
          method: "POST",
          path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/moderation/cases/${encodeURIComponent(params.caseId)}/resolve`,
          body: request.body ?? {}
        });
        return sendProxyResponse(reply, response);
      } catch (error) {
        return reply.code(503).send(
          makeErrorResponse("internal_error", "Social service unavailable", {
            devMode: context.config.DEV_MODE,
            debug: context.config.DEV_MODE
              ? { cause: error instanceof Error ? error.message : "error" }
              : undefined
          })
        );
      }
    }
  );

  app.get("/v1/social/spaces/:spaceId/moderation/audit", async (request, reply) => {
    try {
      const params = request.params as { spaceId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/moderation/audit`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/spaces/:spaceId/analytics", async (request, reply) => {
    try {
      const params = request.params as { spaceId: string };
      const response = await proxyToSocial(context, {
        method: "GET",
        path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/analytics`,
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/social/funnel", async (request, reply) => {
    try {
      const response = await proxyToSocial(context, {
        method: "GET",
        path: "/v1/social/funnel",
        query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
      });
      return sendProxyResponse(reply, response);
    } catch (error) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Social service unavailable", {
          devMode: context.config.DEV_MODE,
          debug: context.config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/social/media/emoji/create", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/emoji/create",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/emoji/pack/create", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/emoji/pack/create",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/emoji/pack/add", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/emoji/pack/add",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/emoji/pack/publish", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/emoji/pack/publish",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/soundpack/create", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/soundpack/create",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/soundpack/add", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/soundpack/add",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/soundpack/publish", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/soundpack/publish",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/soundpack/activate", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/soundpack/activate",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/presence/set_mode", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/presence/set_mode",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/presence/invite", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/presence/invite",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/presence/state", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "GET",
      path: "/v1/social/presence/state",
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/presence", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/presence`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/presence/ping", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/presence/ping`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/profile/visibility", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/profile/visibility`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/leaderboard", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/leaderboard`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/rankings", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/rankings`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/streaks", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/streaks`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/pulse", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/pulse`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/pulse/preferences", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/pulse/preferences`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/pulse/preferences", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/pulse/preferences`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/crews", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/crews`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/crews", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/crews`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/crews/:crewId/join", async (request, reply) => {
    const params = request.params as { crewId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/crews/${encodeURIComponent(params.crewId)}/join`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/crews/:crewId/invite", async (request, reply) => {
    const params = request.params as { crewId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/crews/${encodeURIComponent(params.crewId)}/invite`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/crews/:crewId/leave", async (request, reply) => {
    const params = request.params as { crewId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/crews/${encodeURIComponent(params.crewId)}/leave`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/crews/:crewId/presence", async (request, reply) => {
    const params = request.params as { crewId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/crews/${encodeURIComponent(params.crewId)}/presence`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/challenges", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/challenges`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/challenges", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/challenges`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/challenges/:challengeId/join", async (request, reply) => {
    const params = request.params as { challengeId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/challenges/${encodeURIComponent(params.challengeId)}/join`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/challenges/:challengeId/complete", async (request, reply) => {
    const params = request.params as { challengeId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/challenges/${encodeURIComponent(params.challengeId)}/complete`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/banter/threads", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/banter/threads`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/banter/threads", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/banter/threads`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/banter/threads/:threadId", async (request, reply) => {
    const params = request.params as { threadId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/banter/threads/${encodeURIComponent(params.threadId)}`
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/banter/threads/:threadId/permission", async (request, reply) => {
    const params = request.params as { threadId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/banter/threads/${encodeURIComponent(params.threadId)}/permission`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/banter/threads/:threadId/messages", async (request, reply) => {
    const params = request.params as { threadId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/banter/threads/${encodeURIComponent(params.threadId)}/messages`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/banter/threads/:threadId/send", async (request, reply) => {
    const params = request.params as { threadId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/banter/threads/${encodeURIComponent(params.threadId)}/send`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/banter/messages/:messageId/react", async (request, reply) => {
    const params = request.params as { messageId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/banter/messages/${encodeURIComponent(params.messageId)}/react`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/banter/messages/:messageId/delete", async (request, reply) => {
    const params = request.params as { messageId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/banter/messages/${encodeURIComponent(params.messageId)}/delete`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/banter/messages/:messageId/moderate", async (request, reply) => {
    const params = request.params as { messageId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/banter/messages/${encodeURIComponent(params.messageId)}/moderate`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/spaces/:spaceId/status", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "POST",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/status`,
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/status", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/status`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.get("/v1/social/spaces/:spaceId/rituals/active", async (request, reply) => {
    const params = request.params as { spaceId: string };
    const response = await proxyToSocial(context, {
      method: "GET",
      path: `/v1/social/spaces/${encodeURIComponent(params.spaceId)}/rituals/active`,
      query: request.url.includes("?") ? request.url.slice(request.url.indexOf("?")) : ""
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/ritual/create", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/ritual/create",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/ritual/participate", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/ritual/participate",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/ritual/complete", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/ritual/complete",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/ritual/end", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/ritual/end",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/watch/create_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/watch/create_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/watch/join_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/watch/join_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/watch/end_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/watch/end_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/asset/report", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/asset/report",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/media/asset/moderate", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/media/asset/moderate",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/watch/report", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/watch/report",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/watch/moderate", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/watch/moderate",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/scroll/create_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/scroll/create_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/scroll/join_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/scroll/join_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/scroll/sync_event", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/scroll/sync_event",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/scroll/end_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/scroll/end_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/huddle/create_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/huddle/create_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/hangout/create_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/hangout/create_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/huddle/join_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/huddle/join_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/hangout/join_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/hangout/join_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/huddle/end_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/huddle/end_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/hangout/end_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/hangout/end_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/listen/create_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/listen/create_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/listen/join_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/listen/join_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/listen/broadcast_control", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/listen/broadcast_control",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/listen/end_session", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/listen/end_session",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/session/report", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/session/report",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
  app.post("/v1/social/sync/session/moderate", async (request, reply) => {
    const response = await proxyToSocial(context, {
      method: "POST",
      path: "/v1/social/sync/session/moderate",
      body: request.body ?? {}
    });
    return sendProxyResponse(reply, response);
  });
};
