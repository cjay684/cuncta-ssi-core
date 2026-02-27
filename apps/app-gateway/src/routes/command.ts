import { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { hashCanonicalJson, makeErrorResponse } from "@cuncta/shared";
import { GatewayContext } from "../server.js";
import { log } from "../log.js";

type CommandAction =
  | "sync.hangout.join_session"
  | "banter.message.send"
  | "challenge.complete"
  | "social.space.create";

type ReadyState = "READY" | "MISSING_PROOF" | "DENIED" | "NEEDS_REFINEMENT";

const PLANNER_VERSION = "1.1";
const PLANNER_APP_VERSION_FLOOR = "1.2.0-testnet";
const DEFAULT_POLICY_PIN_FINGERPRINT = "none";
const DEPENDENCY_UNAVAILABLE_REASON = "dependency_unavailable";

const resolveAction = (intent: string): CommandAction | null => {
  const normalized = intent.toLowerCase();
  if (normalized.includes("join") && normalized.includes("hangout")) {
    return "sync.hangout.join_session";
  }
  if (normalized.includes("banter") || normalized.includes("message")) {
    return "banter.message.send";
  }
  if (normalized.includes("challenge") && normalized.includes("complete")) {
    return "challenge.complete";
  }
  if (normalized.includes("open") && normalized.includes("space")) {
    return "social.space.create";
  }
  return null;
};

const nextBestActions = (action: CommandAction) => {
  if (action === "sync.hangout.join_session") {
    return ["Load pulse cards", "Join active space", "Request realtime token"];
  }
  if (action === "banter.message.send") {
    return ["Create or open banter thread", "Request banter permission", "Send fallback via HTTP"];
  }
  if (action === "challenge.complete") {
    return ["Join challenge", "Post verified contribution", "Complete challenge"];
  }
  return ["Create profile", "Join space", "Post first message"];
};

const getSortedCapabilities = (
  requirements: Array<{ vct: string; label?: string }> | null | undefined
) =>
  [...(requirements ?? [])].sort((a, b) => {
    if (a.vct !== b.vct) return a.vct.localeCompare(b.vct);
    return (a.label ?? "").localeCompare(b.label ?? "");
  });

const inferReasonCode = (input: {
  readyState: ReadyState;
  denyReason: string | null;
  action: CommandAction | null;
}) => {
  if (input.readyState === "READY") return null;
  if (input.denyReason === DEPENDENCY_UNAVAILABLE_REASON) return DEPENDENCY_UNAVAILABLE_REASON;
  if (input.readyState === "MISSING_PROOF") return "proof_missing";
  if (input.readyState === "NEEDS_REFINEMENT" || !input.action) return "intent_unrecognized";
  if (input.readyState === "DENIED") return "policy_denied";
  return "denied";
};

const fetchJsonWithTimeout = async (
  context: GatewayContext,
  input: { url: URL; init: RequestInit; timeoutMs: number }
) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => {
    controller.abort("planner_dependency_timeout");
  }, input.timeoutMs);
  timeout.unref?.();
  try {
    const response = await context.fetchImpl(input.url, {
      ...input.init,
      signal: controller.signal
    });
    const payload = (await response.json().catch(() => null)) as unknown;
    if (!response.ok || payload === null) {
      throw new Error("planner_dependency_unavailable");
    }
    return payload;
  } catch (error) {
    if (controller.signal.aborted && controller.signal.reason === "planner_dependency_timeout") {
      throw new Error("planner_dependency_timeout");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
};

const emitCommandPlanAuditEvent = async (input: {
  context: GatewayContext;
  actionId: string | null;
  subjectHash: string;
  readyState: ReadyState;
  denyReason: string | null;
  reasonCode: string | null;
}) => {
  try {
    await input.context.writeCommandCenterAuditEvent({
      id: randomUUID(),
      createdAt: new Date().toISOString(),
      subjectHash: input.subjectHash,
      eventType: "command_plan_requested",
      payload: {
        actionId: input.actionId,
        ready_state: input.readyState,
        denied: input.readyState !== "READY",
        reason_code: input.reasonCode,
        deny_reason: input.denyReason
      }
    });
  } catch (error) {
    log.warn("command.plan.audit_failed", {
      error: error instanceof Error ? error.message : "unknown_error"
    });
  }
};

export const registerCommandRoutes = (app: FastifyInstance, context: GatewayContext) => {
  const ipAllowed = (ip: string | undefined, limitPerMinute: number) => {
    const key = context.hashValue(ip ?? "unknown");
    return context.ipQuotaMinute.consume(key, limitPerMinute, 60_000);
  };

  app.post(
    "/v1/command/plan",
    {
      config: {
        rateLimit: {
          max: context.config.RATE_LIMIT_IP_COMMAND_PER_MIN,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      if (!ipAllowed(request.ip, context.config.RATE_LIMIT_IP_COMMAND_PER_MIN)) {
        return reply.code(429).send({
          error: "rate_limited",
          message: "IP rate limit exceeded"
        });
      }
      const body = (request.body ?? {}) as {
        intent?: string;
        spaceId?: string;
        subjectDid?: string;
        proof?: { presentation?: string; nonce?: string; audience?: string };
      };
      const intent = body.intent?.trim();
      if (!intent) {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Missing intent", {
            devMode: context.config.DEV_MODE
          })
        );
      }
      const action = resolveAction(intent);
      if (!action) {
        const feeQuote = context.getFeeQuoteForPlan({ actionId: null, intent });
        const feeQuoteFingerprint = feeQuote?.quoteFingerprint ?? null;
        const feeScheduleFingerprint = context.feeScheduleFingerprint;
        const paymentsConfigFingerprint = context.paymentsConfigFingerprint;
        const paymentRequest = context.getPaymentRequest({
          feeQuote,
          purposeScope: `command.plan:intent:${intent}`
        });
        const paymentRequestFingerprint = paymentRequest?.paymentRequestFingerprint ?? null;
        const readyState: ReadyState = "NEEDS_REFINEMENT";
        const denyReason =
          "Intent not recognized yet. Try 'join hangout', 'send banter', 'complete challenge', or 'open space'.";
        const reasonCode = inferReasonCode({ readyState, denyReason, action });
        const policyFloorApplied = null;
        const policyPinFingerprint = DEFAULT_POLICY_PIN_FINGERPRINT;
        const planDeterminismKey = hashCanonicalJson({
          plannerVersion: PLANNER_VERSION,
          appVersionFloor: PLANNER_APP_VERSION_FLOOR,
          intent,
          spaceId: body.spaceId ?? null,
          actionId: null,
          policyPinFingerprint,
          policyFloorApplied,
          feeScheduleFingerprint,
          paymentsConfigFingerprint
        });
        const subjectHash = body.subjectDid?.trim()
          ? context.pseudonymizer.didToHash(body.subjectDid.trim())
          : "unknown";
        await emitCommandPlanAuditEvent({
          context,
          actionId: null,
          subjectHash,
          readyState,
          denyReason,
          reasonCode
        });
        void context.maybeCleanupCommandCenterAuditEvents().catch((error) => {
          log.warn("command.plan.cleanup_failed", {
            error: error instanceof Error ? error.message : "unknown_error"
          });
        });
        return reply.send({
          action_plan: [],
          required_capabilities: [],
          ready_state: readyState,
          deny_reason: denyReason,
          next_best_actions: ["Choose a supported intent", "Open Orb quick actions"],
          plannerVersion: PLANNER_VERSION,
          policyFloorApplied,
          policyPinFingerprint,
          planDeterminismKey,
          feeQuote,
          feeQuoteFingerprint,
          feeScheduleFingerprint,
          paymentsConfigFingerprint,
          paymentRequest,
          paymentRequestFingerprint,
          computedAt: new Date().toISOString()
        });
      }
      const feeQuote = context.getFeeQuoteForPlan({ actionId: action, intent });
      const feeQuoteFingerprint = feeQuote?.quoteFingerprint ?? null;
      const feeScheduleFingerprint = context.feeScheduleFingerprint;
      const paymentsConfigFingerprint = context.paymentsConfigFingerprint;
      const paymentRequest = context.getPaymentRequest({
        feeQuote,
        purposeScope: `command.plan:action:${action}`
      });
      const paymentRequestFingerprint = paymentRequest?.paymentRequestFingerprint ?? null;
      let requiredCapabilities: Array<{ vct: string; label?: string }> = [];
      let policyFloorApplied: string | number | null = null;
      let policyPinFingerprint = DEFAULT_POLICY_PIN_FINGERPRINT;
      let dependencyUnavailable = !context.config.POLICY_SERVICE_BASE_URL;
      if (context.config.POLICY_SERVICE_BASE_URL && !dependencyUnavailable) {
        const requirementsUrl = new URL("/v1/requirements", context.config.POLICY_SERVICE_BASE_URL);
        requirementsUrl.searchParams.set("action", action);
        if (body.spaceId) {
          requirementsUrl.searchParams.set("space_id", body.spaceId);
        }
        try {
          const requirementsPayload = (await fetchJsonWithTimeout(context, {
            url: requirementsUrl,
            init: { method: "GET" },
            timeoutMs: context.config.COMMAND_PLANNER_REQUIREMENTS_TIMEOUT_MS
          })) as {
            requirements?: Array<{ vct: string; label?: string }>;
            version?: string | number;
            policyHash?: string;
            policyId?: string;
          } | null;
          requiredCapabilities = getSortedCapabilities(requirementsPayload?.requirements);
          policyFloorApplied = requirementsPayload?.version ?? null;
          policyPinFingerprint =
            typeof requirementsPayload?.policyHash === "string" &&
            requirementsPayload.policyHash.length > 0
              ? requirementsPayload.policyHash
              : hashCanonicalJson({
                  action,
                  policyId: requirementsPayload?.policyId ?? null,
                  policyFloorApplied
                });
        } catch {
          dependencyUnavailable = true;
        }
      }
      let readyState: ReadyState = "MISSING_PROOF";
      let denyReason = "Presentation proof required.";
      if (dependencyUnavailable) {
        readyState = "DENIED";
        denyReason = DEPENDENCY_UNAVAILABLE_REASON;
      } else if (
        body.proof?.presentation &&
        body.proof.nonce &&
        body.proof.audience &&
        context.config.VERIFIER_SERVICE_BASE_URL
      ) {
        const verifyUrl = new URL("/v1/verify", context.config.VERIFIER_SERVICE_BASE_URL);
        verifyUrl.searchParams.set("action", action);
        try {
          const verifyPayload = (await fetchJsonWithTimeout(context, {
            url: verifyUrl,
            init: {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                presentation: body.proof.presentation,
                nonce: body.proof.nonce,
                audience: body.proof.audience,
                context: body.spaceId ? { space_id: body.spaceId } : undefined
              })
            },
            timeoutMs: context.config.COMMAND_PLANNER_VERIFY_TIMEOUT_MS
          })) as { decision?: "ALLOW" | "DENY"; reasons?: string[] } | null;
          if (verifyPayload?.decision === "ALLOW") {
            readyState = "READY";
            denyReason = "";
          } else {
            readyState = "DENIED";
            denyReason = verifyPayload?.reasons?.[0] ?? "Policy denied this action.";
          }
        } catch {
          readyState = "DENIED";
          denyReason = DEPENDENCY_UNAVAILABLE_REASON;
        }
      } else if (body.proof?.presentation && body.proof.nonce && body.proof.audience) {
        readyState = "DENIED";
        denyReason = DEPENDENCY_UNAVAILABLE_REASON;
      }
      const reasonCode = inferReasonCode({ readyState, denyReason, action });
      const planDeterminismKey = hashCanonicalJson({
        plannerVersion: PLANNER_VERSION,
        appVersionFloor: PLANNER_APP_VERSION_FLOOR,
        intent,
        spaceId: body.spaceId ?? null,
        actionId: action,
        requiredCapabilities: requiredCapabilities.map((entry) => ({
          vct: entry.vct,
          label: entry.label ?? null
        })),
        nextBestActions: nextBestActions(action),
        readyState,
        denyReason: denyReason || null,
        policyPinFingerprint,
        policyFloorApplied,
        feeScheduleFingerprint,
        paymentsConfigFingerprint,
        proofShape: {
          hasPresentation: Boolean(body.proof?.presentation),
          hasNonce: Boolean(body.proof?.nonce),
          hasAudience: Boolean(body.proof?.audience)
        }
      });
      const subjectHash = body.subjectDid?.trim()
        ? context.pseudonymizer.didToHash(body.subjectDid.trim())
        : "unknown";
      await emitCommandPlanAuditEvent({
        context,
        actionId: action,
        subjectHash,
        readyState,
        denyReason: denyReason || null,
        reasonCode
      });
      void context.maybeCleanupCommandCenterAuditEvents().catch((error) => {
        log.warn("command.plan.cleanup_failed", {
          error: error instanceof Error ? error.message : "unknown_error"
        });
      });
      return reply.send({
        action_plan: [
          {
            intent,
            action_id: action,
            space_id: body.spaceId ?? null
          }
        ],
        required_capabilities: requiredCapabilities,
        ready_state: readyState,
        deny_reason: denyReason || null,
        next_best_actions: nextBestActions(action),
        plannerVersion: PLANNER_VERSION,
        policyFloorApplied,
        policyPinFingerprint,
        planDeterminismKey,
        feeQuote,
        feeQuoteFingerprint,
        feeScheduleFingerprint,
        paymentsConfigFingerprint,
        paymentRequest,
        paymentRequestFingerprint,
        computedAt: new Date().toISOString()
      });
    }
  );
};
