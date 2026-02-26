import { FastifyInstance } from "fastify";
import { z } from "zod";
import { log } from "../log.js";
import { issueCredential } from "../issuer/issuance.js";
import { config } from "../config.js";
import { makeErrorResponse } from "@cuncta/shared";
import { requireServiceAuth } from "../auth.js";
import net from "node:net";

const issueSchema = z.object({
  subjectDid: z.string().min(3),
  claims: z.record(z.string(), z.unknown()).default({}),
  vct: z.string().min(3)
});

const hasIssuerOverride = (body: unknown) => {
  if (!body || typeof body !== "object") return false;
  const record = body as Record<string, unknown>;
  return "issuerDid" in record || "issuer" in record || "iss" in record;
};

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

export const registerDevRoutes = (app: FastifyInstance) => {
  app.post("/v1/dev/issue", async (request, reply) => {
    const requestId = (request as { requestId?: string }).requestId;
    if (config.NODE_ENV !== "development" || !config.DEV_MODE) {
      return reply.code(404).send(
        makeErrorResponse("invalid_request", "Dev endpoint disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const isLocal =
      isLoopbackAddress(config.SERVICE_BIND_ADDRESS) || isLoopbackAddress(request.ip ?? undefined);
    if (!isLocal) {
      const hasAuth = Boolean(request.headers.authorization);
      if (!hasAuth) {
        return reply.code(404).send(
          makeErrorResponse("invalid_request", "Dev endpoint disabled", {
            devMode: config.DEV_MODE
          })
        );
      }
      await requireServiceAuth(request, reply, { requiredScopes: ["issuer:dev_issue"] });
      if (reply.sent) return;
    }
    if (hasIssuerOverride(request.body)) {
      return reply.code(400).send(
        makeErrorResponse("issuer_not_allowed", "Issuer override not allowed", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = issueSchema.parse(request.body);
    log.info("dev.issue.request", { requestId, vct: body.vct });
    try {
      const result = await issueCredential({
        subjectDid: body.subjectDid,
        claims: body.claims,
        vct: body.vct
      });
      return reply.send({
        eventId: result.eventId,
        credential: result.credential,
        credentialFingerprint: result.credentialFingerprint,
        credentialStatus: result.credentialStatus,
        diagnostics: result.diagnostics
      });
    } catch (error) {
      log.error("dev.issue.failed", { requestId, error });
      const message = error instanceof Error ? error.message : "unknown_error";
      const cause = error instanceof Error ? error.name : "Error";
      const safeMessage = message.replace(/(key|private|secret|jwk|d=)[^\\s]+/gi, "[redacted]");
      const hint =
        message === "issuer_jwk_invalid"
          ? "Check ISSUER_JWK JSON in .env"
          : message === "operator_not_configured"
            ? "Set HEDERA_OPERATOR_ID and HEDERA_OPERATOR_PRIVATE_KEY"
            : message === "status_list_full"
              ? "Increase STATUS_LIST_LENGTH or rotate listId"
              : "Check issuer-service logs for details";
      return reply.code(500).send(
        makeErrorResponse("internal_error", "Issue failed", {
          details: safeMessage,
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE ? { cause, hint } : undefined
        })
      );
    }
  });
};
