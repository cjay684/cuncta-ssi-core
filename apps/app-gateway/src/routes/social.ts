import { FastifyInstance } from "fastify";
import { GatewayContext, createServiceAuthHeader, sendProxyResponse } from "../server.js";
import { makeErrorResponse } from "@cuncta/shared";

const getSocialSecret = (context: GatewayContext) =>
  context.config.SERVICE_JWT_SECRET_SOCIAL ??
  (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);

const proxyToSocial = async (
  context: GatewayContext,
  input: {
    method: "GET" | "POST";
    path: string;
    query?: string;
    body?: unknown;
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
  return context.fetchImpl(url, {
    method: input.method,
    headers: {
      Authorization: authHeader,
      ...(input.method === "POST" ? { "content-type": "application/json" } : {})
    },
    ...(input.method === "POST" ? { body: JSON.stringify(input.body ?? {}) } : {})
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
      "cuncta.sync.session_participant": "Sync session participant capability"
    };
    return reply.send({
      ...payload,
      requirements: (payload.requirements ?? []).map((entry) => ({
        ...entry,
        label: requirementLabels[entry.vct] ?? entry.vct
      }))
    });
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
