import { FastifyInstance } from "fastify";
import { z } from "zod";
import { config } from "../config.js";
import { makeErrorResponse, Oid4vpRequestObjectSchema } from "@cuncta/shared";
import { verifyPresentationCore } from "../core/verifyPresentation.js";
import { log } from "../log.js";

const toOptionalString = (value: unknown) => {
  if (value === undefined || value === null) return undefined;
  const trimmed = String(value).trim();
  return trimmed.length ? trimmed : undefined;
};

const requestQuerySchema = z.object({
  action: z.string().min(1),
  verifier_origin: z.preprocess(toOptionalString, z.string().url().optional())
});

const requirementsSchema = z.object({
  action: z.string(),
  challenge: z.object({
    nonce: z.string(),
    audience: z.string(),
    expires_at: z.string()
  }),
  requirements: z.array(
    z
      .object({
        vct: z.string(),
        disclosures: z.array(z.string()).default([]),
        predicates: z
          .array(
            z.object({
              path: z.string(),
              op: z.string(),
              value: z.unknown().optional()
            })
          )
          .optional()
      })
      .passthrough()
  )
});

const responseBodySchema = z.object({
  action: z.string().min(1),
  presentation: z.string().min(10),
  nonce: z.string().min(10),
  audience: z.string().min(3),
  requestHash: z.string().min(8).optional(),
  requestJwt: z.string().min(10).optional(),
  zk_proofs: z.unknown().optional(),
  context: z.record(z.string(), z.unknown()).optional()
});

const buildOid4vpRequestObject = (payload: z.infer<typeof requirementsSchema>) => {
  return {
    action: payload.action,
    nonce: payload.challenge.nonce,
    audience: payload.challenge.audience,
    expires_at: payload.challenge.expires_at,
    requirements: payload.requirements,
    presentation_definition: {
      id: `cuncta:${payload.action}`,
      input_descriptors: payload.requirements.map((req) => ({
        id: req.vct,
        format: (() => {
          const extras = req as unknown as { formats?: unknown };
          const formats = Array.isArray(extras.formats) ? extras.formats.map(String) : [];
          return formats.includes("di+bbs") ? { "di+bbs": {} } : { "sd-jwt-vc": {} };
        })(),
        disclosures: req.disclosures
      }))
    }
  };
};

export const registerOid4vpRoutes = (app: FastifyInstance) => {
  app.get("/oid4vp/request", async (request, reply) => {
    if (!config.VERIFIER_ENABLE_OID4VP) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "Route disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const { action, verifier_origin } = requestQuerySchema.parse(request.query);

    const url = new URL("/v1/requirements", config.POLICY_SERVICE_BASE_URL);
    url.searchParams.set("action", action);
    if (verifier_origin) {
      url.searchParams.set("verifier_origin", verifier_origin);
    }
    const response = await fetch(url.toString(), { method: "GET" });
    if (!response.ok) {
      const requestId = (request as { requestId?: string }).requestId;
      log.warn("oid4vp.request.requirements_failed", { requestId, status: response.status });
      return reply.code(503).send(
        makeErrorResponse("requirements_unavailable", "Requirements unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    reply.header("cache-control", "no-store");
    const payload = requirementsSchema.parse(await response.json());

    // Minimal OID4VP-ish request object: enough for the in-repo wallet to build the correct SD-JWT presentation.
    const requestObject = buildOid4vpRequestObject(payload);

    // Fail fast if the shape drifts.
    const validated = Oid4vpRequestObjectSchema.parse(requestObject);
    return reply.send(validated);
  });

  app.post("/oid4vp/response", async (request, reply) => {
    if (!config.VERIFIER_ENABLE_OID4VP) {
      return reply.code(404).send(
        makeErrorResponse("not_found", "Route disabled", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = responseBodySchema.parse(request.body);
    const result = await verifyPresentationCore({
      presentation: body.presentation,
      nonce: body.nonce,
      audience: body.audience,
      actionId: body.action,
      context: body.context,
      requestHash: body.requestHash,
      requestJwt: body.requestJwt,
      zkProofs: body.zk_proofs
    });
    return reply.send({
      decision: result.decision,
      reasons: result.reasons,
      policyId: result.policyId,
      policyVersion: result.policyVersion,
      obligationsExecuted: result.obligationsExecuted ?? []
    });
  });
};

export const __test__ = { buildOid4vpRequestObject };

