import { randomBytes, randomUUID, createHash } from "node:crypto";
import { URL } from "node:url";
import { z } from "zod";
import { log } from "../log.js";
import { evaluate, getPolicyForAction } from "../policy/evaluate.js";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { makeErrorResponse } from "@cuncta/shared";
import { requireServiceAuth } from "../auth.js";
import { setPolicyVersionFloor } from "../policy/floor.js";
const requestSchema = z.object({
  subjectDid: z.string().min(3).optional(),
  action: z.string().min(1),
  context: z.record(z.string(), z.unknown()).optional()
});
const floorSetSchema = z.object({
  actionId: z.string().min(1),
  minVersion: z.number().int().min(1)
});
export const registerPolicyRoutes = (app) => {
  app.get("/v1/requirements", async (request, reply) => {
    const query = z
      .object({
        action: z.string().min(1),
        space_id: z.string().uuid().optional(),
        verifier_origin: z.string().min(3).optional()
      })
      .parse(request.query);
    let policy;
    try {
      policy = await getPolicyForAction(query.action);
    } catch (error) {
      if (error instanceof Error && error.message === "policy_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("policy_integrity_failed", "Policy integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
    if (!policy) {
      return reply.code(404).send(
        makeErrorResponse("policy_not_found", "Policy not found", {
          devMode: config.DEV_MODE
        })
      );
    }
    const db = await getDb();
    const credentialTypes = await db("credential_types")
      .whereIn(
        "vct",
        policy.logic.requirements.map((req) => req.vct)
      )
      .select("vct", "sd_defaults", "display", "purpose_limits", "presentation_templates");
    const requirements = policy.logic.requirements.map((req) => {
      const catalog = credentialTypes.find((row) => row.vct === req.vct);
      const extras = req;
      return {
        vct: req.vct,
        issuer: req.issuer,
        formats: Array.isArray(extras.formats) ? extras.formats.map(String) : ["dc+sd-jwt"],
        zk_predicates: Array.isArray(extras.zk_predicates) ? extras.zk_predicates : [],
        disclosures: req.disclosures,
        revocation: req.revocation,
        predicates: req.predicates,
        context_predicates: req.context_predicates ?? [],
        purpose_limits: catalog?.purpose_limits ?? {},
        presentation_templates: catalog?.presentation_templates ?? {},
        sd_defaults: catalog?.sd_defaults ?? []
      };
    });
    const responseContext = query.space_id ? { space_id: query.space_id } : undefined;

    const nonce = randomBytes(32).toString("base64url");
    let audience = `cuncta.action:${query.action}`;
    if (query.verifier_origin) {
      try {
        const origin = new URL(query.verifier_origin).origin;
        audience = `origin:${origin}`;
      } catch {
        return reply.code(400).send(
          makeErrorResponse("invalid_request", "Invalid verifier origin", {
            devMode: config.DEV_MODE
          })
        );
      }
    }
    const expiresAt = new Date(Date.now() + config.CHALLENGE_TTL_SECONDS * 1000).toISOString();
    const challengeHash = createHash("sha256").update(nonce).digest("hex");
    const policyHash = policy.policyHash;
    await db("verification_challenges").where("expires_at", "<", new Date().toISOString()).del();
    await db("verification_challenges").insert({
      challenge_id: randomUUID(),
      challenge_hash: challengeHash,
      action_id: query.action,
      policy_id: policy.policyId,
      policy_version: policy.version,
      policy_hash: policyHash,
      audience,
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    });
    const requestId = request.requestId;
    log.info("policy.requirements", {
      requestId,
      action: query.action,
      policyId: policy.policyId,
      policyVersion: policy.version
    });
    const obligations = (policy.logic.obligations ?? []).map((ob) => {
      const o = ob ?? {};
      if (o.type === "CAPABILITY_SIGNAL" && typeof o.domain !== "string") {
        const signal = typeof o.signal === "string" ? o.signal : "";
        if (signal.includes(".space.") && typeof responseContext?.space_id === "string") {
          return { ...o, domain: `space:${responseContext.space_id}` };
        }
      }
      return o;
    });
    return reply.send({
      action: query.action,
      action_id: query.action,
      policyId: policy.policyId,
      policyHash,
      version: policy.version,
      binding: policy.logic.binding ?? { mode: "kb-jwt", require: true },
      context: responseContext,
      requirements,
      obligations,
      challenge: {
        nonce,
        audience,
        expires_at: expiresAt
      }
    });
  });
  app.post("/v1/policy/evaluate", async (request, reply) => {
    const body = requestSchema.parse(request.body);
    let result;
    try {
      result = await evaluate({
        action: body.action,
        context: body.context
      });
    } catch (error) {
      if (error instanceof Error && error.message === "policy_integrity_failed") {
        return reply.code(503).send(
          makeErrorResponse("policy_integrity_failed", "Policy integrity check failed", {
            devMode: config.DEV_MODE
          })
        );
      }
      throw error;
    }
    const requestId = request.requestId;
    log.info("policy.evaluate", {
      requestId,
      action: body.action,
      requirementCount: result.requirements.length
    });
    return reply.send(result);
  });

  app.post("/v1/admin/policy/floor", async (request, reply) => {
    await requireServiceAuth(request, reply, { requireAdminScope: ["policy:floor_set"] });
    if (reply.sent) return;
    const body = floorSetSchema.parse(request.body ?? {});
    await setPolicyVersionFloor(body.actionId, body.minVersion);
    return reply.send({
      actionId: body.actionId,
      minVersion: body.minVersion
    });
  });
};
//# sourceMappingURL=policy.js.map
