import { FastifyInstance, FastifyReply } from "fastify";
import net from "node:net";
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { SignJWT, jwtVerify } from "jose";
import { TopicMessageSubmitTransaction, Transaction } from "@hashgraph/sdk";
import { makeErrorResponse } from "@cuncta/shared";
import {
  GatewayContext,
  GatewayRequest,
  createServiceAuthHeader,
  requireDeviceHash,
  sendProxyResponse
} from "../server.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";

const issueSchema = z.object({
  subjectDid: z.string().min(3),
  vct: z.string().min(3),
  claims: z.record(z.string(), z.unknown()).default({})
});

const userPaysRequestSchema = z.object({
  network: z.enum(["testnet", "previewnet", "mainnet"]),
  publicKeyMultibase: z.string().regex(/^z[1-9A-HJ-NP-Za-km-z]+$/),
  topicId: z.string().optional(),
  options: z
    .object({
      topicManagement: z.enum(["shared", "single"]).default("shared"),
      includeServiceEndpoints: z.boolean().default(false)
    })
    .default({ topicManagement: "shared", includeServiceEndpoints: false })
});

const userPaysSubmitSchema = z.object({
  handoffToken: z.string().min(10),
  signedTransactionB64u: z.string().regex(/^[A-Za-z0-9_-]+$/)
});

const revokeSchema = z
  .object({
    eventId: z.string().min(3).optional(),
    credentialFingerprint: z.string().min(10).optional()
  })
  .refine((value) => value.eventId || value.credentialFingerprint, {
    message: "Missing revoke target"
  });

const deviceRequired = (request: GatewayRequest, context: GatewayContext) => {
  const deviceHash = requireDeviceHash(request, context);
  if (!deviceHash) {
    return makeErrorResponse("invalid_request", "Missing device id", {
      devMode: context.config.DEV_MODE
    });
  }
  return null;
};

const getServiceSecret = (context: GatewayContext, target: "did" | "issuer") => {
  if (target === "did") {
    return (
      context.config.SERVICE_JWT_SECRET_DID ??
      (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET
        ? context.config.SERVICE_JWT_SECRET
        : undefined)
    );
  }
  return (
    context.config.SERVICE_JWT_SECRET_ISSUER ??
    (context.config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? context.config.SERVICE_JWT_SECRET : undefined)
  );
};

const ipAllowed = (request: GatewayRequest, context: GatewayContext, limitPerMinute: number) => {
  const ip = request.ip ?? "unknown";
  const key = context.hashValue(ip);
  return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
};

const enforceSponsorBudget = async (
  reply: FastifyReply,
  context: GatewayContext,
  kind: "did_create" | "issue",
  requestId?: string
) => {
  try {
    const result = await context.reserveSponsorBudget(kind, { requestId });
    if (!result.allowed) {
      const message =
        result.reason === "kill_switch" ? "Sponsor operations disabled" : "Sponsor budget exceeded";
      const status = result.reason === "kill_switch" ? 503 : 429;
      reply
        .code(status)
        .send(
          makeErrorResponse(
            result.reason === "kill_switch" ? "sponsor_kill_switch" : "sponsor_budget_exceeded",
            message
          )
        );
      return false;
    }
    if (!("reservation" in result) || !result.reservation) {
      reply
        .code(503)
        .send(makeErrorResponse("sponsor_budget_unavailable", "Sponsor budget unavailable"));
      return false;
    }
    metrics.incCounter("sponsor_budget_reserved_total", { kind });
    return result.reservation;
  } catch {
    reply
      .code(503)
      .send(makeErrorResponse("sponsor_budget_unavailable", "Sponsor budget unavailable"));
    return false;
  }
};

const ensureSponsoredOnboardingAllowed = (reply: FastifyReply, context: GatewayContext) => {
  if (context.config.ALLOW_SPONSORED_ONBOARDING) return true;
  reply.code(403).send(
    makeErrorResponse("sponsored_onboarding_disabled", "Self-funded required", {
      details: "Sponsored onboarding is disabled"
    })
  );
  return false;
};

const ensureSelfFundedOnboardingAllowed = (reply: FastifyReply, context: GatewayContext) => {
  if (context.config.ALLOW_SELF_FUNDED_ONBOARDING) return true;
  reply.code(403).send(
    makeErrorResponse("self_funded_onboarding_disabled", "Self-funded disabled", {
      details: "Self-funded onboarding is disabled"
    })
  );
  return false;
};

const normalizeIp = (value: string) => (value.startsWith("::ffff:") ? value.slice(7) : value);

const ipToBytes = (value: string) => {
  const normalized = normalizeIp(value);
  const ipType = net.isIP(normalized);
  if (ipType === 4) {
    return Uint8Array.from(normalized.split(".").map((part) => Number(part)));
  }
  if (ipType === 6) {
    const expanded = normalized.includes("::") ? expandIpv6(normalized) : normalized;
    const parts = expanded.split(":");
    if (parts.length !== 8) return null;
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 8; i += 1) {
      const hex = parts[i].padStart(4, "0");
      bytes[i * 2] = Number.parseInt(hex.slice(0, 2), 16);
      bytes[i * 2 + 1] = Number.parseInt(hex.slice(2), 16);
    }
    return bytes;
  }
  return null;
};

const expandIpv6 = (value: string) => {
  const [left, right] = value.split("::");
  const leftParts = left ? left.split(":") : [];
  const rightParts = right ? right.split(":") : [];
  const missing = 8 - (leftParts.length + rightParts.length);
  const zeros = Array.from({ length: Math.max(0, missing) }, () => "0");
  return [...leftParts, ...zeros, ...rightParts].join(":");
};

const matchCidr = (ip: string, cidr: string) => {
  const [base, prefixRaw] = cidr.split("/");
  const prefix = Number(prefixRaw);
  if (!Number.isInteger(prefix)) return false;
  const ipBytes = ipToBytes(ip);
  const baseBytes = ipToBytes(base);
  if (!ipBytes || !baseBytes || ipBytes.length !== baseBytes.length) return false;
  if (ipBytes.length === 4 && (prefix < 0 || prefix > 32)) return false;
  if (ipBytes.length === 16 && (prefix < 0 || prefix > 128)) return false;
  const byteCount = Math.floor(prefix / 8);
  const bitCount = prefix % 8;
  for (let i = 0; i < byteCount; i += 1) {
    if (ipBytes[i] !== baseBytes[i]) return false;
  }
  if (bitCount > 0) {
    const mask = 0xff << (8 - bitCount);
    if ((ipBytes[byteCount] & mask) !== (baseBytes[byteCount] & mask)) return false;
  }
  return true;
};

const ipAllowedByAllowlist = (ip: string, allowlist: string[]) => {
  const normalized = normalizeIp(ip);
  for (const entry of allowlist) {
    if (!entry) continue;
    const trimmed = entry.trim();
    if (!trimmed) continue;
    if (trimmed.includes("/")) {
      if (matchCidr(normalized, trimmed)) return true;
    } else if (normalized === normalizeIp(trimmed)) {
      return true;
    }
  }
  return false;
};

const ensureContractE2eAllowed = (
  request: GatewayRequest,
  reply: FastifyReply,
  context: GatewayContext
) => {
  if (!context.config.CONTRACT_E2E_ENABLED) {
    return reply.code(404).send(
      makeErrorResponse("not_found", "Not found", {
        devMode: context.config.DEV_MODE
      })
    );
  }
  const token = request.headers["x-contract-e2e-token"];
  if (typeof token !== "string" || token !== context.config.CONTRACT_E2E_ADMIN_TOKEN) {
    return reply.code(403).send(
      makeErrorResponse("forbidden", "Forbidden", {
        devMode: context.config.DEV_MODE
      })
    );
  }
  const allowlist = context.config.CONTRACT_E2E_IP_ALLOWLIST;
  if (allowlist.length) {
    const rawIp = request.ip ?? "";
    if (!ipAllowedByAllowlist(rawIp, allowlist)) {
      return reply.code(403).send(
        makeErrorResponse("forbidden", "Forbidden", {
          devMode: context.config.DEV_MODE
        })
      );
    }
  }
  return null;
};

const usedUserPaysTokens = new Map<string, number>();
const pruneUsedTokens = () => {
  const now = Date.now();
  for (const [key, value] of usedUserPaysTokens.entries()) {
    if (value <= now) {
      usedUserPaysTokens.delete(key);
    }
  }
};

const userPaysTokenSchema = z.object({
  jti: z.string().uuid(),
  network: z.enum(["testnet", "previewnet", "mainnet"]),
  topicId: z.string().optional(),
  publicKeyMultibase: z.string(),
  options: z.object({
    topicManagement: z.enum(["shared", "single"]),
    includeServiceEndpoints: z.boolean()
  }),
  exp: z.number().int(),
  iat: z.number().int()
});

const getHandoffSecret = (context: GatewayContext) =>
  new TextEncoder().encode(context.config.USER_PAYS_HANDOFF_SECRET ?? "");

const createUserPaysToken = async (input: {
  network: "testnet" | "previewnet" | "mainnet";
  topicId?: string;
  publicKeyMultibase: string;
  options: { topicManagement: "shared" | "single"; includeServiceEndpoints: boolean };
  ttlSeconds: number;
  context: GatewayContext;
}) => {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + input.ttlSeconds;
  const jti = randomUUID();
  const payload = {
    jti,
    network: input.network,
    topicId: input.topicId,
    publicKeyMultibase: input.publicKeyMultibase,
    options: input.options,
    iat,
    exp
  };
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(getHandoffSecret(input.context));
  return { token, expiresAt: new Date(exp * 1000).toISOString() };
};

const verifyUserPaysToken = async (token: string, context: GatewayContext) => {
  pruneUsedTokens();
  const { payload } = await jwtVerify(token, getHandoffSecret(context), {
    algorithms: ["HS256"]
  });
  const parsed = userPaysTokenSchema.parse(payload);
  if (usedUserPaysTokens.has(parsed.jti)) {
    throw new Error("user_pays_token_reused");
  }
  usedUserPaysTokens.set(parsed.jti, parsed.exp * 1000);
  return parsed;
};

export const registerOnboardRoutes = (app: FastifyInstance, context: GatewayContext) => {
  metrics.incCounter(
    "rate_limit_rejects_total",
    {
      route: "/v1/onboard/did/create/request",
      kind: "ip"
    },
    0
  );
  metrics.incCounter(
    "rate_limit_rejects_total",
    {
      route: "/v1/onboard/did/create/submit",
      kind: "ip"
    },
    0
  );
  metrics.incCounter(
    "rate_limit_rejects_total",
    {
      route: "/v1/onboard/issue",
      kind: "ip"
    },
    0
  );
  metrics.incCounter(
    "rate_limit_rejects_total",
    {
      route: "/v1/onboard/did/create/user-pays/request",
      kind: "ip"
    },
    0
  );
  metrics.incCounter(
    "rate_limit_rejects_total",
    {
      route: "/v1/onboard/did/create/user-pays/submit",
      kind: "ip"
    },
    0
  );
  metrics.incCounter(
    "device_quota_rejects_total",
    {
      route: "/v1/onboard/did/create/submit",
      kind: "daily"
    },
    0
  );
  metrics.incCounter(
    "device_quota_rejects_total",
    {
      route: "/v1/onboard/issue",
      kind: "minute"
    },
    0
  );
  metrics.incCounter(
    "rate_limit_rejects_total",
    {
      route: "/v1/onboard/revoke",
      kind: "ip"
    },
    0
  );

  app.post(
    "/v1/onboard/did/create/request",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_DID_REQUEST_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      const req = request as GatewayRequest;
      if (!ipAllowed(req, context, context.config.RATE_LIMIT_IP_DID_REQUEST_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/did/create/request",
          kind: "ip"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "IP rate limit exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceError = deviceRequired(req, context);
      if (deviceError) {
        return reply.code(400).send(deviceError);
      }
      const serviceSecret = getServiceSecret(context, "did");
      if (!serviceSecret) {
        return reply.code(503).send(
          makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const authHeader = await createServiceAuthHeader(context, {
        audience: context.config.SERVICE_JWT_AUDIENCE_DID ?? context.config.SERVICE_JWT_AUDIENCE,
        secret: serviceSecret,
        scope: ["did:create_request"]
      });
      const url = new URL("/v1/dids/create/request", context.config.DID_SERVICE_BASE_URL);
      const response = await context.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: authHeader
        },
        body: JSON.stringify(request.body ?? {})
      });
      if (!response.ok) {
        log.warn("onboard.did.request.failed", {
          requestId: req.requestId,
          status: response.status
        });
      }
      return sendProxyResponse(reply, response);
    }
  );

  app.post(
    "/v1/onboard/did/create/submit",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_DID_SUBMIT_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ensureSponsoredOnboardingAllowed(reply, context)) return;
      const req = request as GatewayRequest;
      if (!ipAllowed(req, context, context.config.RATE_LIMIT_IP_DID_SUBMIT_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/did/create/submit",
          kind: "ip"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "IP rate limit exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceError = deviceRequired(req, context);
      if (deviceError) {
        return reply.code(400).send(deviceError);
      }
      const deviceHash = req.deviceHash!;
      const allowed = context.deviceQuotaDaily.consume(
        deviceHash,
        context.config.RATE_LIMIT_DEVICE_DID_PER_DAY,
        24 * 60 * 60 * 1000
      );
      if (!allowed) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/did/create/submit",
          kind: "device_daily"
        });
        metrics.incCounter("device_quota_rejects_total", {
          route: "/v1/onboard/did/create/submit",
          kind: "daily"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "Device DID quota exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const reservation = await enforceSponsorBudget(reply, context, "did_create", req.requestId);
      if (!reservation) return;
      const serviceSecret = getServiceSecret(context, "did");
      if (!serviceSecret) {
        return reply.code(503).send(
          makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const authHeader = await createServiceAuthHeader(context, {
        audience: context.config.SERVICE_JWT_AUDIENCE_DID ?? context.config.SERVICE_JWT_AUDIENCE,
        secret: serviceSecret,
        scope: ["did:create_submit"]
      });
      const url = new URL("/v1/dids/create/submit", context.config.DID_SERVICE_BASE_URL);
      const response = await context.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: authHeader
        },
        body: JSON.stringify(request.body ?? {})
      });
      if (response.ok) {
        const commit = await context.commitSponsorBudgetReservation(reservation.id);
        if (!commit.committed) {
          metrics.incCounter("sponsor_budget_commit_fail_total", { kind: "did_create" });
          return reply
            .code(503)
            .send(makeErrorResponse("internal_error", "Sponsor budget unavailable"));
        }
        metrics.incCounter("sponsor_budget_committed_total", {
          kind: "did_create",
          idempotent: commit.idempotent
        });
      } else {
        await context.revertSponsorBudgetReservation(reservation.id);
        metrics.incCounter("sponsor_budget_reverted_total", { kind: "did_create" });
      }
      if (!response.ok) {
        log.warn("onboard.did.submit.failed", {
          requestId: req.requestId,
          status: response.status
        });
      }
      return sendProxyResponse(reply, response);
    }
  );

  app.post(
    "/v1/onboard/issue",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_ISSUE_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ensureSponsoredOnboardingAllowed(reply, context)) return;
      const req = request as GatewayRequest;
      if (!ipAllowed(req, context, context.config.RATE_LIMIT_IP_ISSUE_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/issue",
          kind: "ip"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "IP rate limit exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceError = deviceRequired(req, context);
      if (deviceError) {
        return reply.code(400).send(deviceError);
      }
      const body = issueSchema.parse(request.body ?? {});
      if (!context.config.GATEWAY_ALLOWED_VCTS.includes(body.vct)) {
        return reply.code(403).send(
          makeErrorResponse("invalid_request", "VCT not allowed", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceHash = req.deviceHash!;
      const allowed = context.deviceQuotaMinute.consume(
        deviceHash,
        context.config.RATE_LIMIT_DEVICE_ISSUE_PER_MIN,
        60_000
      );
      if (!allowed) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/issue",
          kind: "device_minute"
        });
        metrics.incCounter("device_quota_rejects_total", {
          route: "/v1/onboard/issue",
          kind: "minute"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "Device issue quota exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const reservation = await enforceSponsorBudget(reply, context, "issue", req.requestId);
      if (!reservation) return;
      const serviceSecret = getServiceSecret(context, "issuer");
      if (!serviceSecret) {
        return reply.code(503).send(
          makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const authHeader = await createServiceAuthHeader(context, {
        audience: context.config.SERVICE_JWT_AUDIENCE_ISSUER ?? context.config.SERVICE_JWT_AUDIENCE,
        secret: serviceSecret,
        scope: ["issuer:internal_issue"]
      });
      const url = new URL("/v1/internal/issue", context.config.ISSUER_SERVICE_BASE_URL);
      const response = await context.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: authHeader
        },
        body: JSON.stringify(body)
      });
      if (response.ok) {
        const commit = await context.commitSponsorBudgetReservation(reservation.id);
        if (!commit.committed) {
          metrics.incCounter("sponsor_budget_commit_fail_total", { kind: "issue" });
          return reply
            .code(503)
            .send(makeErrorResponse("internal_error", "Sponsor budget unavailable"));
        }
        metrics.incCounter("sponsor_budget_committed_total", {
          kind: "issue",
          idempotent: commit.idempotent
        });
      } else {
        await context.revertSponsorBudgetReservation(reservation.id);
        metrics.incCounter("sponsor_budget_reverted_total", { kind: "issue" });
      }
      if (!response.ok) {
        log.warn("onboard.issue.failed", {
          requestId: req.requestId,
          status: response.status
        });
      }
      return sendProxyResponse(reply, response);
    }
  );

  app.post(
    "/v1/onboard/did/create/user-pays/request",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_DID_REQUEST_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ensureSelfFundedOnboardingAllowed(reply, context)) return;
      const req = request as GatewayRequest;
      if (!ipAllowed(req, context, context.config.RATE_LIMIT_IP_DID_REQUEST_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/did/create/user-pays/request",
          kind: "ip"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "IP rate limit exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceError = deviceRequired(req, context);
      if (deviceError) {
        return reply.code(400).send(deviceError);
      }
      const body = userPaysRequestSchema.parse(request.body ?? {});
      if (body.network !== context.config.HEDERA_NETWORK) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Network mismatch", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const topicId =
        body.options.topicManagement === "shared"
          ? (context.config.HEDERA_DID_TOPIC_ID ?? body.topicId)
          : body.topicId;
      if (body.options.topicManagement === "shared" && !topicId) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing shared topic id", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      if (
        context.config.HEDERA_DID_TOPIC_ID &&
        body.options.topicManagement === "shared" &&
        topicId &&
        topicId !== context.config.HEDERA_DID_TOPIC_ID
      ) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Topic id mismatch", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const requestMeta = await createUserPaysToken({
        context,
        network: body.network,
        topicId,
        publicKeyMultibase: body.publicKeyMultibase,
        options: body.options,
        ttlSeconds: context.config.USER_PAYS_REQUEST_TTL_SECONDS
      });
      return reply.send({
        handoffToken: requestMeta.token,
        expiresAt: requestMeta.expiresAt,
        network: body.network,
        topicId,
        publicKeyMultibase: body.publicKeyMultibase,
        options: body.options
      });
    }
  );

  app.post(
    "/v1/onboard/did/create/user-pays/submit",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_DID_SUBMIT_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ensureSelfFundedOnboardingAllowed(reply, context)) return;
      const req = request as GatewayRequest;
      if (!ipAllowed(req, context, context.config.RATE_LIMIT_IP_DID_SUBMIT_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/did/create/user-pays/submit",
          kind: "ip"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "IP rate limit exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceError = deviceRequired(req, context);
      if (deviceError) {
        return reply.code(400).send(deviceError);
      }
      const deviceHash = req.deviceHash!;
      const allowed = context.deviceQuotaDaily.consume(
        deviceHash,
        context.config.RATE_LIMIT_DEVICE_DID_PER_DAY,
        24 * 60 * 60 * 1000
      );
      if (!allowed) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/did/create/user-pays/submit",
          kind: "device_daily"
        });
        metrics.incCounter("device_quota_rejects_total", {
          route: "/v1/onboard/did/create/user-pays/submit",
          kind: "daily"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "Device DID quota exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const body = userPaysSubmitSchema.parse(request.body ?? {});
      const signedBytes = Buffer.from(body.signedTransactionB64u, "base64url");
      if (signedBytes.length > context.config.USER_PAYS_MAX_TX_BYTES) {
        return reply.code(413).send(
          makeErrorResponse("invalid_request", "Signed transaction too large", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const txHash = createHash("sha256").update(signedBytes).digest("hex");
      try {
        const entry = await verifyUserPaysToken(body.handoffToken, context);
        if (entry.network !== context.config.HEDERA_NETWORK) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Network mismatch", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const transaction = Transaction.fromBytes(signedBytes);
        if (!(transaction instanceof TopicMessageSubmitTransaction)) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Unsupported transaction type", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const topicId = transaction.topicId?.toString();
        if (entry.topicId && topicId !== entry.topicId) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Topic id mismatch", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const maxFeeTinybars = transaction.maxTransactionFee?.toTinybars();
        const maxFeeValue =
          maxFeeTinybars === undefined
            ? undefined
            : typeof maxFeeTinybars === "number"
              ? maxFeeTinybars
              : typeof (maxFeeTinybars as { toNumber?: () => number }).toNumber === "function"
                ? (maxFeeTinybars as { toNumber: () => number }).toNumber()
                : Number(maxFeeTinybars.toString());
        if (maxFeeValue !== undefined && maxFeeValue > context.config.USER_PAYS_MAX_FEE_TINYBARS) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Max fee too high", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        const result = await context.submitUserPaysTransaction({
          network: entry.network,
          signedTransactionBytes: signedBytes
        });
        return reply.send({
          transactionId: result.transactionId,
          status: result.status ?? "UNKNOWN",
          requestId: entry.jti
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message.startsWith("JWT") || message.includes("user_pays_token")) {
          return reply.code(400).send(
            makeErrorResponse("invalid_request", "Invalid handoff token", {
              devMode: context.config.DEV_MODE
            })
          );
        }
        log.error("onboard.user_pays.submit.failed", { requestId: req.requestId, txHash, error });
        return reply.code(503).send(
          makeErrorResponse("self_funded_submit_failed", "Submit failed", {
            devMode: context.config.DEV_MODE
          })
        );
      }
    }
  );

  app.post(
    "/v1/onboard/revoke",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_ISSUE_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      const req = request as GatewayRequest;
      const contractError = ensureContractE2eAllowed(req, reply, context);
      if (contractError) return;
      if (!ensureSponsoredOnboardingAllowed(reply, context)) return;
      if (!ipAllowed(req, context, context.config.RATE_LIMIT_IP_ISSUE_PER_MIN)) {
        metrics.incCounter("rate_limit_rejects_total", {
          route: "/v1/onboard/revoke",
          kind: "ip"
        });
        return reply.code(429).send(
          makeErrorResponse("rate_limited", "IP rate limit exceeded", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const deviceError = deviceRequired(req, context);
      if (deviceError) {
        return reply.code(400).send(deviceError);
      }
      let body;
      try {
        body = revokeSchema.parse(request.body ?? {});
      } catch (error) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing revoke target", {
            devMode: context.config.DEV_MODE,
            debug: context.config.DEV_MODE
              ? { cause: error instanceof Error ? error.message : "Error" }
              : undefined
          })
        );
      }
      const serviceSecret = getServiceSecret(context, "issuer");
      if (!serviceSecret) {
        return reply.code(503).send(
          makeErrorResponse("service_auth_unavailable", "Service auth unavailable", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const authHeader = await createServiceAuthHeader(context, {
        audience: context.config.SERVICE_JWT_AUDIENCE_ISSUER ?? context.config.SERVICE_JWT_AUDIENCE,
        secret: serviceSecret,
        scope: ["issuer:revoke"]
      });
      const url = new URL("/v1/revoke", context.config.ISSUER_SERVICE_BASE_URL);
      const response = await context.fetchImpl(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: authHeader
        },
        body: JSON.stringify(body)
      });
      if (!response.ok) {
        log.warn("onboard.revoke.failed", {
          requestId: req.requestId,
          status: response.status
        });
      }
      return sendProxyResponse(reply, response);
    }
  );
};
