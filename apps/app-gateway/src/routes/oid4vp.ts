import { FastifyInstance } from "fastify";
import { GatewayContext, createServiceAuthHeader, sendProxyResponse } from "../server.js";
import { metrics } from "../metrics.js";
import { makeErrorResponse, Oid4vpRequestObjectSchema } from "@cuncta/shared";
import { log } from "../log.js";
import { randomUUID, createHash } from "node:crypto";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { getDb } from "../db.js";
import { z } from "zod";
import { getZkStatement } from "@cuncta/zk-registry";

const ipAllowed = (ip: string | undefined, context: GatewayContext, limitPerMinute: number) => {
  const key = context.hashValue(ip ?? "unknown");
  return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
};

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

const computeZkContextFromRequirements = async (requirements: unknown[]) => {
  const predicateIds = requirements
    .flatMap((r: unknown) => {
      const rr = (r ?? {}) as Record<string, unknown>;
      return Array.isArray(rr.zk_predicates) ? rr.zk_predicates : [];
    })
    .map((p: unknown) => (p ?? {}) as Record<string, unknown>)
    .map((p) => String(p.id ?? "").trim())
    .filter((id) => id.length > 0);

  let requiresCurrentDay = false;
  for (const statementId of predicateIds) {
    try {
      const st = await getZkStatement(statementId);
      requiresCurrentDay ||= Boolean(st.definition.zk_context_requirements.current_day?.required);
    } catch {
      // Policy verification / verifier will fail closed if the statement is missing/unavailable.
      // Gateway keeps generating the request so the caller gets a deterministic denial later.
    }
  }

  if (requiresCurrentDay) {
    return { current_day: Math.floor(Date.now() / 86_400_000) };
  }
  return undefined;
};

const consumeRequestHashOnce = async (requestHash: string) => {
  const db = await getDb();
  const now = new Date().toISOString();
  const updated = await db("oid4vp_request_hashes")
    .where({ request_hash: requestHash })
    .whereNull("consumed_at")
    .andWhere("expires_at", ">", now)
    .update({ consumed_at: now });
  if (!updated) {
    throw new Error("oid4vp_request_consumed_or_expired");
  }
};

const registerRequestHash = async (requestJwt: string, expiresAtIso: string) => {
  const db = await getDb();
  const requestHash = sha256Hex(requestJwt);
  await db("oid4vp_request_hashes")
    .insert({
      request_hash: requestHash,
      expires_at: expiresAtIso,
      consumed_at: null,
      created_at: new Date().toISOString()
    })
    .onConflict("request_hash")
    .ignore();
  return requestHash;
};

const verifyResponseJwt = async (jwt: string) => {
  const header = decodeProtectedHeader(jwt);
  if (header.alg !== "EdDSA") {
    throw new Error("response_jwt_invalid_alg");
  }
  const decoded = decodeJwt(jwt) as Record<string, unknown>;
  const cnf = decoded.cnf as { jwk?: Record<string, unknown> } | undefined;
  if (!cnf?.jwk) {
    throw new Error("response_jwt_missing_cnf");
  }
  const key = await importJWK(cnf.jwk as never, "EdDSA");
  const verified = await jwtVerify(jwt, key, { algorithms: ["EdDSA"] });
  return verified.payload as Record<string, unknown>;
};

const parsePresentationSubmission = (raw: unknown): { descriptor_map: Array<{ id: string; path: string }> } => {
  const value = typeof raw === "string" ? JSON.parse(raw) : raw;
  if (!value || typeof value !== "object") {
    throw new Error("presentation_submission_invalid");
  }
  const record = value as Record<string, unknown>;
  const map = record.descriptor_map;
  if (!Array.isArray(map)) throw new Error("presentation_submission_invalid");
  const parsed = map
    .map((entry) => (entry && typeof entry === "object" ? (entry as Record<string, unknown>) : null))
    .filter(Boolean)
    .map((entry) => ({ id: String(entry!.id ?? ""), path: String(entry!.path ?? "") }))
    .filter((e) => e.id.length > 0 && e.path.length > 0);
  if (!parsed.length) throw new Error("presentation_submission_invalid");
  return { descriptor_map: parsed };
};

const validatePresentationSubmissionMinimal = (input: {
  presentationDefinition: Record<string, unknown>;
  presentationSubmission: unknown;
}) => {
  const pd = input.presentationDefinition as { input_descriptors?: Array<{ id?: string }> };
  const firstDescriptorId = String(pd?.input_descriptors?.[0]?.id ?? "");
  if (!firstDescriptorId) {
    throw new Error("presentation_definition_invalid");
  }
  const submission = parsePresentationSubmission(input.presentationSubmission);
  const match = submission.descriptor_map.find((d) => d.id === firstDescriptorId);
  if (!match) {
    throw new Error("presentation_submission_descriptor_mismatch");
  }
  // Minimal path validation: we only support a single vp_token value.
  if (!["$.vp_token", "$.vp_token[0]"].includes(match.path)) {
    throw new Error("presentation_submission_path_invalid");
  }
};

export const registerOid4vpRoutes = (app: FastifyInstance, context: GatewayContext) => {
  if (!context.config.VERIFIER_SERVICE_BASE_URL) return;

  // Standard-ish OID4VP request surface: returns OAuth/OID4VP authorization request parameters.
  // Wallets typically consume this as a URL; for the CLI and integration tests we return JSON.
  app.get("/oid4vp/authorize", async (request, reply) => {
    const incomingQuery = new URL(request.url, "http://localhost").searchParams;
    const action = incomingQuery.get("action") ?? "";
    const verifierOrigin = incomingQuery.get("verifier_origin") ?? "";
    if (!action) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Missing action", { devMode: context.config.DEV_MODE })
      );
    }
    if (context.config.NODE_ENV === "production" && !verifierOrigin) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Missing verifier_origin", { devMode: context.config.DEV_MODE })
      );
    }
    const policyUrl = new URL("/v1/requirements", context.config.POLICY_SERVICE_BASE_URL);
    policyUrl.searchParams.set("action", action);
    if (verifierOrigin) {
      policyUrl.searchParams.set("verifier_origin", verifierOrigin);
    }
    const requirementsRes = await context.fetchImpl(policyUrl.toString(), { method: "GET" });
    if (!requirementsRes.ok) {
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Policy service unavailable", {
          devMode: context.config.DEV_MODE
        })
      );
    }
    const policyPayload = (await requirementsRes.json()) as {
      action?: string;
      policyHash?: string;
      challenge?: { nonce?: string; audience?: string; expires_at?: string };
      requirements?: unknown[];
    };
    if (!policyPayload.challenge?.nonce || !policyPayload.challenge?.audience || !policyPayload.challenge?.expires_at) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Invalid policy response", { devMode: context.config.DEV_MODE })
      );
    }
    if (!context.config.GATEWAY_SIGN_OID4VP_REQUEST || !context.config.APP_GATEWAY_PUBLIC_BASE_URL) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Request signing disabled", { devMode: context.config.DEV_MODE })
      );
    }
    const state = randomUUID();
    const responseMode =
      (incomingQuery.get("response_mode") ?? "direct_post.jwt").trim() || "direct_post.jwt";
    const responseUri = new URL("/oid4vp/response", context.config.APP_GATEWAY_PUBLIC_BASE_URL).toString();
    const clientId = policyPayload.challenge.audience.startsWith("origin:")
      ? policyPayload.challenge.audience.slice("origin:".length)
      : undefined;
    const presentationDefinition = {
      id: `cuncta:${String(policyPayload.action ?? action)}`,
      input_descriptors: (Array.isArray(policyPayload.requirements) ? policyPayload.requirements : []).map(
        (r: unknown) => {
          const rr = (r ?? {}) as Record<string, unknown>;
          const formats = Array.isArray(rr.formats) ? rr.formats.map(String) : [];
          const disclosures = Array.isArray(rr.disclosures) ? rr.disclosures.map(String) : [];
          const allowSd = formats.includes("dc+sd-jwt");
          const allowDi = formats.includes("di+bbs");
          return {
            id: String(rr.vct ?? ""),
            // Allow both formats when policy allows negotiation; wallet chooses a satisfiable one.
            format: allowSd && allowDi ? { "sd-jwt-vc": {}, "di+bbs": {} } : allowDi ? { "di+bbs": {} } : { "sd-jwt-vc": {} },
            disclosures
          };
        }
      )
    };
    const hasZkPredicates = (Array.isArray(policyPayload.requirements) ? policyPayload.requirements : []).some(
      (r: unknown) => {
        const rr = (r ?? {}) as Record<string, unknown>;
        return Array.isArray(rr.zk_predicates) && rr.zk_predicates.length > 0;
      }
    );
    if (hasZkPredicates && !context.config.ALLOW_EXPERIMENTAL_ZK) {
      return reply.code(503).send(
        makeErrorResponse("forbidden", "ZK predicates disabled", { devMode: context.config.DEV_MODE })
      );
    }
    // Registry-driven: only include `zk_context` keys required by the referenced statements.
    const zkContext = hasZkPredicates
      ? await computeZkContextFromRequirements(Array.isArray(policyPayload.requirements) ? policyPayload.requirements : [])
      : undefined;
    const verifierSecret =
      context.config.SERVICE_JWT_SECRET_VERIFIER ??
      (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined);
    if (!verifierSecret) {
      return reply.code(503).send(
        makeErrorResponse("internal_error", "Service auth unavailable", { devMode: context.config.DEV_MODE })
      );
    }
    const authHeader = await createServiceAuthHeader(context, {
      audience: context.config.SERVICE_JWT_AUDIENCE_VERIFIER ?? context.config.SERVICE_JWT_AUDIENCE,
      secret: verifierSecret,
      scope: ["verifier:request_sign"]
    });
    const signUrl = new URL("/v1/request/sign", context.config.VERIFIER_SERVICE_BASE_URL);
    const signRes = await context.fetchImpl(signUrl.toString(), {
      method: "POST",
      headers: { "content-type": "application/json", authorization: authHeader },
      body: JSON.stringify({
        nonce: policyPayload.challenge.nonce,
        audience: policyPayload.challenge.audience,
        exp: Math.floor(Date.parse(policyPayload.challenge.expires_at) / 1000),
        action_id: policyPayload.action ?? action,
        policyHash: policyPayload.policyHash ?? "",
        iss: context.config.APP_GATEWAY_PUBLIC_BASE_URL.replace(/\/$/, ""),
        state,
        response_uri: responseUri,
        response_mode: responseMode,
        response_type: "vp_token",
        client_id: clientId,
        client_id_scheme: clientId ? "redirect_uri" : undefined,
        presentation_definition: presentationDefinition,
        zk_context: zkContext
      })
    });
    if (!signRes.ok) {
      return reply.code(503).send(makeErrorResponse("internal_error", "Request signing failed"));
    }
    const signed = (await signRes.json()) as { request_jwt?: string };
    if (!signed.request_jwt) {
      return reply.code(503).send(makeErrorResponse("internal_error", "Request signing failed"));
    }
    await registerRequestHash(signed.request_jwt, policyPayload.challenge.expires_at);
    const requestUri = `${context.config.APP_GATEWAY_PUBLIC_BASE_URL.replace(
      /\/$/,
      ""
    )}/oid4vp/request_uri?request=${encodeURIComponent(signed.request_jwt)}`;
    const mode = incomingQuery.get("mode") ?? "request_uri";
    const out: Record<string, unknown> = {
      response_type: "vp_token",
      scope: "openid",
      response_mode: responseMode,
      client_id: clientId,
      client_id_scheme: clientId ? "redirect_uri" : undefined,
      nonce: policyPayload.challenge.nonce,
      state
    };
    if (mode === "request") {
      out.request = signed.request_jwt;
    } else {
      out.request_uri = requestUri;
    }
    reply.header("cache-control", "no-store");
    return reply.send(out);
  });

  // Standard request_uri dereference endpoint.
  // Design constraint: we do NOT persist raw request objects; we store only request hashes + TTL.
  // The wallet provides the request JWT as a query param; we enforce that it was minted by this gateway.
  app.get("/oid4vp/request_uri", async (request, reply) => {
    const q = z.object({ request: z.string().min(10) }).parse(request.query ?? {});
    const requestHash = sha256Hex(q.request);
    const db = await getDb();
    const row = await db("oid4vp_request_hashes").where({ request_hash: requestHash }).first();
    if (!row) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "Request not found", { devMode: context.config.DEV_MODE })
      );
    }
    reply.header("cache-control", "no-store");
    // Per spec, request_uri returns the request object (JWT) as a string body.
    reply.header("content-type", "application/oauth-authz-req+jwt");
    return reply.send(q.request);
  });

  app.get(
    "/oid4vp/request",
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
          route: "/oid4vp/request",
          kind: "ip"
        });
        return reply.code(429).send({
          error: "rate_limited",
          message: "IP rate limit exceeded"
        });
      }

      // Canonical consumer request endpoint.
      // We source requirements from policy-service (to get policyHash + audience binding),
      // then (optionally) attach a signed `request_jwt` via verifier-service signing.
      if (!context.config.POLICY_SERVICE_BASE_URL) {
        return reply.code(503).send(
          makeErrorResponse("requirements_unavailable", "Request unavailable", {
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
        url.searchParams.set("verifier_origin", new URL(context.config.APP_GATEWAY_PUBLIC_BASE_URL).origin);
      }

      const requirementsRes = await context.fetchImpl(url.toString(), { method: "GET" });
      if (!requirementsRes.ok) {
        return reply.code(503).send(
          makeErrorResponse("requirements_unavailable", "Request unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }

      const policyPayload = (await requirementsRes.json()) as {
        action?: string;
        policyHash?: string;
        challenge?: { nonce?: string; audience?: string; expires_at?: string };
        requirements?: unknown[];
        request_jwt?: string;
      };

      const state = randomUUID();
      const responseMode =
        (incomingQuery.get("response_mode") ?? "direct_post.jwt").trim() || "direct_post.jwt";
      const responseUri =
        context.config.APP_GATEWAY_PUBLIC_BASE_URL
          ? new URL("/oid4vp/response", context.config.APP_GATEWAY_PUBLIC_BASE_URL).toString()
          : "http://localhost/oid4vp/response";
      const clientId = policyPayload.challenge?.audience?.startsWith("origin:")
        ? policyPayload.challenge.audience.slice("origin:".length)
        : undefined;
      const presentationDefinition = {
        id: `cuncta:${String(policyPayload.action ?? "")}`,
        input_descriptors: (Array.isArray(policyPayload.requirements) ? policyPayload.requirements : []).map(
          (r: unknown) => {
            const rr = (r ?? {}) as Record<string, unknown>;
            const formats = Array.isArray(rr.formats) ? rr.formats.map(String) : [];
            const disclosures = Array.isArray(rr.disclosures) ? rr.disclosures.map(String) : [];
            return {
              id: String(rr.vct ?? ""),
              format: formats.includes("di+bbs") ? { "di+bbs": {} } : { "sd-jwt-vc": {} },
              disclosures
            };
          }
        )
      };
      const hasZkPredicates = (Array.isArray(policyPayload.requirements) ? policyPayload.requirements : []).some(
        (r: unknown) => {
          const rr = (r ?? {}) as Record<string, unknown>;
          return Array.isArray(rr.zk_predicates) && rr.zk_predicates.length > 0;
        }
      );
      if (hasZkPredicates && !context.config.ALLOW_EXPERIMENTAL_ZK) {
        return reply.code(503).send(
          makeErrorResponse("forbidden", "ZK predicates disabled", { devMode: context.config.DEV_MODE })
        );
      }
      const zkContext = hasZkPredicates
        ? await computeZkContextFromRequirements(Array.isArray(policyPayload.requirements) ? policyPayload.requirements : [])
        : undefined;

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
                iss: context.config.APP_GATEWAY_PUBLIC_BASE_URL.replace(/\/$/, ""),
                state,
                response_uri: responseUri,
                response_mode: responseMode,
                response_type: "vp_token",
                client_id: clientId,
                client_id_scheme: clientId ? "redirect_uri" : undefined,
                presentation_definition: presentationDefinition,
                zk_context: zkContext
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
            log.warn("oid4vp.request.sign_failed", {
              requestId,
              error: err instanceof Error ? err.message : "unknown"
            });
          }
        }
      }

      const req = {
        action: String(policyPayload.action ?? ""),
        nonce: String(policyPayload.challenge?.nonce ?? ""),
        audience: String(policyPayload.challenge?.audience ?? ""),
        expires_at: String(policyPayload.challenge?.expires_at ?? ""),
        request_jwt: policyPayload.request_jwt,
        request_uri: policyPayload.request_jwt
          ? `${(context.config.APP_GATEWAY_PUBLIC_BASE_URL ?? "http://localhost").replace(/\/$/, "")}/oid4vp/request_uri?request=${encodeURIComponent(
              policyPayload.request_jwt
            )}`
          : undefined,
        state,
        client_id: clientId,
        response_uri: responseUri,
        response_mode: responseMode,
        response_type: "vp_token",
        requirements: Array.isArray(policyPayload.requirements) ? policyPayload.requirements : [],
        presentation_definition: presentationDefinition,
        zk_context: zkContext
      };

      // Fail fast if the shape drifts (wallet relies on this being strict/stable).
      const validated = Oid4vpRequestObjectSchema.parse(req);

      // If request_jwt exists, it is the canonical request; store only its hash for one-time semantics.
      if (validated.request_jwt && validated.expires_at) {
        await registerRequestHash(validated.request_jwt, validated.expires_at);
      }
      reply.header("cache-control", "no-store");
      return reply.send(validated);
    }
  );

  app.post(
    "/oid4vp/response",
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
          route: "/oid4vp/response",
          kind: "ip"
        });
        return reply.code(429).send({
          error: "rate_limited",
          message: "IP rate limit exceeded"
        });
      }
      // Standard: accept form-encoded direct_post and direct_post.jwt.
      // Legacy: accept JSON body with { action, presentation, nonce, audience } and proxy as-is.
      const contentType = String(request.headers["content-type"] ?? "");
      const isJson = contentType.includes("application/json");
      if (!isJson && request.body && typeof request.body === "object") {
        try {
          const body = request.body as Record<string, unknown>;
          const responseJwt = typeof body.response === "string" ? body.response : undefined;
          const vpToken = typeof body.vp_token === "string" ? body.vp_token : undefined;
          const submission = body.presentation_submission;
          const requestJwt = typeof body.request === "string" ? body.request : undefined;

          let effectiveRequestJwt = requestJwt ?? "";
          let effectiveVpToken = vpToken ?? "";
          let effectiveSubmission: unknown = submission;
          let effectiveZkProofs: unknown = undefined;

          if (responseJwt) {
            const responsePayload = await verifyResponseJwt(responseJwt);
            effectiveVpToken = String(responsePayload.vp_token ?? "");
            effectiveSubmission = responsePayload.presentation_submission;
            effectiveRequestJwt = String(responsePayload.request ?? "");
            effectiveZkProofs = (responsePayload as Record<string, unknown>).zk_proofs;
          }
          if (!effectiveRequestJwt || effectiveRequestJwt.length < 10) {
            return reply.code(400).send(
              makeErrorResponse("invalid_request", "Missing request object", { devMode: context.config.DEV_MODE })
            );
          }
          if (!effectiveVpToken || effectiveVpToken.length < 10) {
            return reply.code(400).send(
              makeErrorResponse("invalid_request", "Missing vp_token", { devMode: context.config.DEV_MODE })
            );
          }
          // One-time semantics for the request object.
          const requestHash = sha256Hex(effectiveRequestJwt);
          try {
            await consumeRequestHashOnce(requestHash);
          } catch {
            return reply.send({ decision: "DENY", reasons: ["challenge_consumed"] });
          }
          // We intentionally decode unverified: the request hash binds integrity, and request JWT signature is wallet-verified.
          const reqPayload = decodeJwt(effectiveRequestJwt) as Record<string, unknown>;
          const nonce = String(reqPayload.nonce ?? "");
          const audience = String(reqPayload.audience ?? "");
          const action = String(reqPayload.action_id ?? "");
          const presentationDefinition = (reqPayload.presentation_definition ?? {}) as Record<string, unknown>;
          try {
            validatePresentationSubmissionMinimal({
              presentationDefinition,
              presentationSubmission: effectiveSubmission
            });
          } catch (error) {
            return reply.send({
              decision: "DENY",
              reasons: [error instanceof Error ? error.message : "presentation_submission_invalid"]
            });
          }
          const url = new URL("/oid4vp/response", context.config.VERIFIER_SERVICE_BASE_URL);
          const controller = new AbortController();
          const timeout = setTimeout(
            () => controller.abort("verifier_proxy_timeout"),
            context.config.VERIFIER_PROXY_TIMEOUT_MS
          );
          timeout.unref?.();
          let response: Response;
          try {
            response = await context.fetchImpl(url, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                action,
                presentation: effectiveVpToken,
                nonce,
                audience,
                requestHash,
                requestJwt: effectiveRequestJwt,
                zk_proofs: effectiveZkProofs
              }),
              signal: controller.signal
            });
          } catch {
            return reply.send({ decision: "DENY", reasons: ["not_allowed"] });
          } finally {
            clearTimeout(timeout);
          }
          return sendProxyResponse(reply, response);
        } catch (error) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Invalid OID4VP response", {
              details: context.config.DEV_MODE ? (error instanceof Error ? error.message : "error") : undefined,
              devMode: context.config.DEV_MODE
            })
          );
        }
      }

      const url = new URL("/oid4vp/response", context.config.VERIFIER_SERVICE_BASE_URL);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort("verifier_proxy_timeout"), context.config.VERIFIER_PROXY_TIMEOUT_MS);
      timeout.unref?.();
      let response: Response;
      try {
        response = await context.fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(request.body ?? {}),
          signal: controller.signal
        });
      } catch {
        // Fail closed: if verifier is unavailable, deny without leaking upstream state.
        return reply.send({ decision: "DENY", reasons: ["not_allowed"] });
      } finally {
        clearTimeout(timeout);
      }
      return sendProxyResponse(reply, response);
    }
  );
};

