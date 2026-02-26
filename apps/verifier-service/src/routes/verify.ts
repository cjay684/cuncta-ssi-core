import { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import { log } from "../log.js";
import { sha256Hex } from "../crypto/sha256.js";
import { makeErrorResponse } from "@cuncta/shared";
import { metrics } from "../metrics.js";
import {
  isCoreHttpError,
  verifyPresentationCore,
  __test__ as __core_test__
} from "../core/verifyPresentation.js";

const verifyBodySchema = z.object({
  presentation: z.string().min(10).max(config.VERIFY_MAX_PRESENTATION_BYTES),
  nonce: z.string().min(10).max(config.VERIFY_MAX_NONCE_CHARS),
  audience: z.string().min(3).max(config.VERIFY_MAX_AUDIENCE_CHARS),
  context: z.record(z.string(), z.unknown()).optional()
});

export const registerVerifyRoutes = (app: FastifyInstance) => {
  // Legacy verify endpoint. Consumer/public surface is OID4VP.
  // If the verifier is intentionally deployed as a public service, do not expose /v1/verify.
  if (config.NODE_ENV === "production" && config.PUBLIC_SERVICE) {
    return;
  }

  app.post("/v1/verify", async (request, reply) => {
    const action = z.object({ action: z.string().min(1) }).parse(request.query);
    const body = verifyBodySchema.parse(request.body);
    const tokenHash = sha256Hex(body.presentation);
    const requestId = (request as { requestId?: string }).requestId;
    log.info("verify.request", { requestId, action: action.action, tokenHash });

    try {
      const result = await verifyPresentationCore({
        presentation: body.presentation,
        nonce: body.nonce,
        audience: body.audience,
        actionId: action.action,
        context: body.context
      });
      return reply.send({
        decision: result.decision,
        reasons: result.reasons,
        obligationExecutionId: result.obligationExecutionId ?? null,
        obligationsExecuted: result.obligationsExecuted ?? []
      });
    } catch (error) {
      if (isCoreHttpError(error)) {
        return reply.code(error.statusCode).send(
          makeErrorResponse(error.code as never, error.message, {
            devMode: config.DEV_MODE
          })
        );
      }
      log.error("verify.failed", { requestId, error });
      metrics.incCounter("verify_invalid_total", { action: action.action });
      return reply.send({ decision: "DENY", reasons: ["verification_failed"] });
    }
  });
};

export const __test__ = {
  ...__core_test__
};
