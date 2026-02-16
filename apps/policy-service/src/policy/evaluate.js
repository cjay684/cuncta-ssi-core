import { z } from "zod";
import { getDb } from "../db.js";
export const PredicateSchema = z.object({
  path: z.string().min(1),
  op: z.enum(["eq", "neq", "gte", "lte", "in", "exists"]),
  value: z.unknown().optional()
});
export const IssuerRuleSchema = z.object({
  mode: z.enum(["allowlist", "env"]),
  allowed: z.array(z.string()).optional(),
  env: z.string().optional()
});
export const RequirementSchema = z.object({
  vct: z.string().min(1),
  issuer: IssuerRuleSchema.optional(),
  disclosures: z.array(z.string()).default([]),
  predicates: z.array(PredicateSchema).default([]),
  revocation: z.object({ required: z.boolean() }).optional()
});
export const PolicyLogicSchema = z.object({
  binding: z
    .object({
      mode: z.enum(["kb-jwt", "nonce"]).default("kb-jwt"),
      require: z.boolean().default(true)
    })
    .optional(),
  requirements: z.array(RequirementSchema).default([]),
  obligations: z
    .array(
      z
        .object({
          type: z.string().min(1)
        })
        .passthrough()
    )
    .default([])
});
export const getPolicyForAction = async (actionId) => {
  const db = await getDb();
  const record = await db("policies")
    .where({ action_id: actionId, enabled: true })
    .orderBy("version", "desc")
    .first();
  if (!record) {
    return null;
  }
  return {
    policyId: record.policy_id,
    actionId: record.action_id,
    version: record.version,
    enabled: record.enabled,
    logic: PolicyLogicSchema.parse(record.logic)
  };
};
export const evaluate = async (input) => {
  const record = await getPolicyForAction(input.action);
  if (!record) {
    return { action: input.action, requirements: [], obligations: [], binding: undefined };
  }
  return {
    action: input.action,
    requirements: record.logic.requirements,
    obligations: record.logic.obligations,
    binding: record.logic.binding
  };
};
//# sourceMappingURL=evaluate.js.map
