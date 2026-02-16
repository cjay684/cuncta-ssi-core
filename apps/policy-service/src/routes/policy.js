import { randomBytes, randomUUID } from "node:crypto";
import { z } from "zod";
import { log } from "../log.js";
import { evaluate, getPolicyForAction } from "../policy/evaluate.js";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { hashCanonicalJson } from "@cuncta/shared";
const requestSchema = z.object({
  subjectDid: z.string().min(3).optional(),
  action: z.string().min(1),
  context: z.record(z.string(), z.unknown()).optional()
});
export const registerPolicyRoutes = (app) => {
  app.get("/v1/requirements", async (request, reply) => {
    const query = z.object({ action: z.string().min(1) }).parse(request.query);
    const policy = await getPolicyForAction(query.action);
    if (!policy) {
      return reply.code(404).send({ error: "policy_not_found" });
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
      return {
        vct: req.vct,
        issuer: req.issuer,
        disclosures: req.disclosures,
        revocation: req.revocation,
        predicates: req.predicates,
        purpose_limits: catalog?.purpose_limits ?? {},
        presentation_templates: catalog?.presentation_templates ?? {},
        sd_defaults: catalog?.sd_defaults ?? []
      };
    });
    const nonce = randomBytes(32).toString("base64url");
    const audience = `cuncta.action:${query.action}`;
    const expiresAt = new Date(Date.now() + config.CHALLENGE_TTL_SECONDS * 1000).toISOString();
    const challengeHash = hashCanonicalJson({ nonce });
    await db("verification_challenges").where("expires_at", "<", new Date().toISOString()).del();
    await db("verification_challenges").insert({
      challenge_id: randomUUID(),
      challenge_hash: challengeHash,
      action_id: query.action,
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    });
    return reply.send({
      action: query.action,
      action_id: query.action,
      policyId: policy.policyId,
      version: policy.version,
      binding: policy.logic.binding ?? { mode: "kb-jwt", require: true },
      requirements,
      obligations: policy.logic.obligations ?? [],
      challenge: {
        nonce,
        audience,
        expires_at: expiresAt
      }
    });
  });
  app.post("/v1/policy/evaluate", async (request, reply) => {
    const body = requestSchema.parse(request.body);
    const result = await evaluate({
      action: body.action
    });
    log.info("policy.evaluate", {
      action: body.action,
      requirementCount: result.requirements.length
    });
    return reply.send(result);
  });
};
//# sourceMappingURL=policy.js.map
