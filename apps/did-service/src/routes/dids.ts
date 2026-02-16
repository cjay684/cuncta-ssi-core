import { FastifyInstance } from "fastify";
import { z } from "zod";
import * as Registrar from "@hiero-did-sdk/registrar";
import * as Resolver from "@hiero-did-sdk/resolver";
import * as Core from "@hiero-did-sdk/core";
import { config } from "../config.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { sha256Hex } from "../crypto/sha256.js";
import { assertOperatorConfigured, buildRegistrarProviders } from "../hedera/client.js";
import { DidCreateOptions, EphemeralStateStore } from "../state/ephemeralState.js";
import { requireServiceAuth } from "../auth.js";
import { makeErrorResponse } from "@cuncta/shared";

const registrarModule = Registrar as unknown as { default?: typeof Registrar };
const registrar = registrarModule.default ?? Registrar;
const resolverModule = Resolver as unknown as { default?: typeof Resolver };
const resolver = resolverModule.default ?? Resolver;
const coreModule = Core as unknown as { default?: typeof Core };
const core = coreModule.default ?? Core;
type RegistrarProviders = Parameters<typeof registrar.generateCreateDIDRequest>[1];

const stateStore = new EphemeralStateStore(config.DID_REQUEST_TTL_MS);

const base64UrlToBytes = (value: string) => Buffer.from(value, "base64url");
const bytesToBase64Url = (value: Uint8Array) => Buffer.from(value).toString("base64url");

const createRequestSchema = z.object({
  network: z.enum(["testnet", "previewnet", "mainnet"]).default(config.HEDERA_NETWORK),
  publicKeyMultibase: z.string().regex(/^z[1-9A-HJ-NP-Za-km-z]+$/),
  options: z
    .object({
      topicManagement: z.enum(["shared", "single"]).default("shared"),
      includeServiceEndpoints: z.boolean().default(false)
    })
    .default({ topicManagement: "shared", includeServiceEndpoints: false })
});

const submitRequestSchema = z.object({
  state: z.string().uuid(),
  signatureB64u: z.string().regex(/^[A-Za-z0-9_-]+$/),
  waitForVisibility: z.boolean().optional()
});

const submitQuerySchema = z.object({
  waitForVisibility: z
    .preprocess((value) => {
      if (value === undefined || value === null || value === "") return undefined;
      if (value === "true") return true;
      if (value === "false") return false;
      return undefined;
    }, z.boolean().optional())
    .optional()
});

const resolveParamsSchema = z.object({
  did: z.string().min(8)
});

const extractPayloadToSign = (result: Registrar.CreateDIDRequest) => {
  return result.signingRequest.serializedPayload;
};

const extractCreateResponse = (result: Registrar.CreateDIDRequest) => {
  return {
    payloadToSign: result.signingRequest.serializedPayload,
    publicKeyMultibase: result.signingRequest.multibasePublicKey,
    createdAt: new Date().toISOString(),
    operationState: result.state
  };
};

const extractSubmitResponse = (
  result: Registrar.CreateDIDResult,
  fallbackTopicId: string | undefined,
  visibility: "pending" | "confirmed"
) => {
  const did = result.did;
  const didDocument = result.didDocument;
  const parsed = core.parseDID(did);
  const topicId = parsed.topicId ?? fallbackTopicId ?? "";
  const transactionId = (result as { transactionId?: string }).transactionId ?? "";
  const consensusTimestamp = (result as { consensusTimestamp?: string }).consensusTimestamp;

  const response: {
    did: string;
    didDocument?: unknown;
    visibility: "pending" | "confirmed";
    hedera: {
      topicId: string;
      transactionId: string;
      consensusTimestamp?: string;
    };
  } = {
    did,
    didDocument,
    visibility,
    hedera: {
      topicId,
      transactionId,
      ...(consensusTimestamp ? { consensusTimestamp } : {})
    }
  };
  if (visibility === "pending" && (didDocument === null || didDocument === undefined)) {
    delete response.didDocument;
  }
  return response;
};

const normalizeOptions = (options: DidCreateOptions) => ({
  topicManagement: options.topicManagement,
  includeServiceEndpoints: options.includeServiceEndpoints
});

export const registerDidRoutes = (app: FastifyInstance) => {
  app.post("/v1/dids/create/request", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["did:create_request"] });
    if (reply.sent) return;
    const requestId = (request as { requestId?: string }).requestId;
    const body = createRequestSchema.parse(request.body);
    try {
      const registrarOptions: Registrar.GenerateCreateDIDRequestOptions = {
        multibasePublicKey: body.publicKeyMultibase,
        topicId: body.options.topicManagement === "shared" ? config.HEDERA_DID_TOPIC_ID : undefined
      };
      if (body.network !== config.HEDERA_NETWORK) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Network mismatch", {
            devMode: config.DEV_MODE
          })
        );
      }

      const response = await registrar.generateCreateDIDRequest(
        registrarOptions,
        buildRegistrarProviders(config.HEDERA_NETWORK) as RegistrarProviders
      );

      const payloadToSign = extractPayloadToSign(response);
      const created = extractCreateResponse(response);

      if (created.publicKeyMultibase !== body.publicKeyMultibase) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Public key mismatch", {
            devMode: config.DEV_MODE
          })
        );
      }

      const { entry, state } = stateStore.create({
        publicKeyMultibase: body.publicKeyMultibase,
        network: body.network,
        payloadToSign,
        operationState: created.operationState,
        options: normalizeOptions(body.options)
      });

      log.info("did.create.request", {
        requestId,
        state,
        network: body.network,
        payloadSha256: sha256Hex(payloadToSign)
      });

      return reply.send({
        state,
        signingRequest: {
          publicKeyMultibase: created.publicKeyMultibase,
          alg: "EdDSA",
          payloadToSignB64u: bytesToBase64Url(payloadToSign),
          createdAt: entry.createdAt ?? created.createdAt
        }
      });
    } catch (error) {
      log.error("did.create.request.failed", { requestId, error });
      return reply.code(500).send(
        makeErrorResponse("internal_error", "Create request failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "Error" }
            : undefined
        })
      );
    }
  });

  app.post("/v1/dids/create/submit", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["did:create_submit"] });
    if (reply.sent) return;
    const requestId = (request as { requestId?: string }).requestId;
    const body = submitRequestSchema.parse(request.body);
    const query = submitQuerySchema.parse(request.query ?? {});
    const stateEntry = stateStore.consume(body.state);

    if (!stateEntry) {
      return reply.code(404).send(
        makeErrorResponse("invalid_request", "State not found", {
          devMode: config.DEV_MODE
        })
      );
    }
    try {
      assertOperatorConfigured();
    } catch (error) {
      log.error("did.create.submit.operator_missing", { requestId, error });
      return reply.code(500).send(
        makeErrorResponse("internal_error", "Operator not configured", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "Error" }
            : undefined
        })
      );
    }

    const signatureBytes = base64UrlToBytes(body.signatureB64u);

    log.info("did.create.submit", {
      requestId,
      state: body.state,
      payloadSha256: sha256Hex(stateEntry.payloadToSign),
      signatureSha256: sha256Hex(signatureBytes)
    });

    try {
      const defaultWaitForVisibility =
        config.HEDERA_NETWORK === "testnet" ? false : config.DID_WAIT_FOR_VISIBILITY;
      const waitForVisibility =
        body.waitForVisibility ?? query.waitForVisibility ?? defaultWaitForVisibility;

      const response = await registrar.submitCreateDIDRequest(
        {
          state: stateEntry.operationState as Registrar.SubmitCreateDIDRequestOptions["state"],
          signature: signatureBytes,
          visibilityTimeoutMs: config.DID_VISIBILITY_TIMEOUT_MS,
          waitForDIDVisibility: waitForVisibility
        },
        buildRegistrarProviders(config.HEDERA_NETWORK) as RegistrarProviders
      );

      return reply.send(
        extractSubmitResponse(
          response,
          stateEntry.options.topicManagement === "shared" ? config.HEDERA_DID_TOPIC_ID : undefined,
          waitForVisibility ? "confirmed" : "pending"
        )
      );
    } catch (error) {
      log.error("did.create.submit.failed", { requestId, error });
      return reply.code(500).send(
        makeErrorResponse("internal_error", "Create submit failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "Error" }
            : undefined
        })
      );
    }
  });

  app.get("/v1/dids/resolve/:did", async (request, reply) => {
    const requestId = (request as { requestId?: string }).requestId;
    const params = resolveParamsSchema.parse(request.params);
    const startedAt = Date.now();
    metrics.incCounter("did_resolution_poll_total", {}, 1);
    try {
      const response = await resolver.resolveDID(params.did);
      const didDocument = response ?? {};
      const elapsedMs = Math.max(1, Date.now() - startedAt);
      metrics.setGauge("did_resolution_last_elapsed_ms", {}, elapsedMs);
      if (didDocument && Object.keys(didDocument).length > 0) {
        metrics.incCounter("did_resolution_success_total", {}, 1);
      }
      return reply.send({ didDocument });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      metrics.incCounter("did_resolution_last_error_total", {}, 1);
      if (message.toLowerCase().includes("timeout") || message.toLowerCase().includes("exceeded")) {
        metrics.incCounter("did_resolution_timeout_total", {}, 1);
      }
      log.error("did.resolve.failed", { requestId, error, did: params.did });
      return reply.code(500).send(
        makeErrorResponse("internal_error", "Resolve failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? { cause: error instanceof Error ? error.message : "Error" }
            : undefined
        })
      );
    }
  });
};
