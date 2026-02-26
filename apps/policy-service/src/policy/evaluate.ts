import { z } from "zod";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { ensurePolicyIntegrity } from "./integrity.js";
import { getPolicyVersionFloor } from "./floor.js";
import { applyComplianceProfileOverlay, selectComplianceProfile } from "../complianceProfiles.js";

export const PredicateSchema = z.object({
  path: z.string().min(1),
  op: z.enum(["eq", "neq", "gte", "lte", "in", "exists"]),
  value: z.unknown().optional()
});

export const ContextPredicateSchema = z.object({
  left: z.string().min(1),
  right: z.string().min(1),
  op: z.enum(["eq"])
});

export const IssuerRuleSchema = z.object({
  mode: z.enum(["allowlist", "env", "trust_registry"]),
  allowed: z.array(z.string()).optional(),
  env: z.string().optional(),
  // Data-driven trust enforcement: verifier checks issuer DID against the signed trust registry.
  registry_id: z.string().min(1).optional(),
  trust_mark: z.string().min(1).optional()
});

export const RequirementSchema = z.object({
  vct: z.string().min(1),
  issuer: IssuerRuleSchema.optional(),
  // Optional negotiation: SD-JWT remains default if omitted.
  formats: z.array(z.string().min(1)).default(["dc+sd-jwt"]),
  // Optional ZK predicates required to satisfy this requirement (e.g., age>=18).
  zk_predicates: z
    .array(
      z.object({
        id: z.string().min(1),
        params: z.record(z.string(), z.unknown()).optional()
      })
    )
    .default([]),
  disclosures: z.array(z.string()).default([]),
  predicates: z.array(PredicateSchema).default([]),
  context_predicates: z.array(ContextPredicateSchema).default([]),
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

export type PolicyLogic = z.infer<typeof PolicyLogicSchema>;

export type PolicyRecord = {
  policyId: string;
  actionId: string;
  version: number;
  enabled: boolean;
  logic: PolicyLogic;
  policyHash: string;
};

export const getPolicyForAction = async (actionId: string): Promise<PolicyRecord | null> => {
  if (actionId.startsWith("dev.") && !config.DEV_MODE) {
    return null;
  }
  const db = await getDb();
  const floor = config.POLICY_VERSION_FLOOR_ENFORCED ? await getPolicyVersionFloor(actionId) : 0;
  const query = db("policies").where({ action_id: actionId, enabled: true });
  if (floor > 0) {
    query.andWhere("version", ">=", floor);
  }
  const record = await query.orderBy("version", "desc").first();
  if (!record) {
    return null;
  }
  const integrity = await ensurePolicyIntegrity(record);
  return {
    policyId: record.policy_id,
    actionId: record.action_id,
    version: record.version,
    enabled: record.enabled,
    logic: PolicyLogicSchema.parse(record.logic),
    policyHash: integrity.policyHash
  };
};

export const evaluate = async (input: { action: string; context?: Record<string, unknown> }) => {
  const profile = selectComplianceProfile(input.context);
  const record = await getPolicyForAction(input.action);
  if (!record) {
    return {
      action: input.action,
      policyId: undefined,
      policyVersion: undefined,
      requirements: [],
      obligations: [],
      binding: undefined,
      context: input.context,
      profileId: profile.profile_id,
      profileFlags: profile.flags
    };
  }
  const overlay = applyComplianceProfileOverlay({ profile, logic: record.logic });
  return {
    action: input.action,
    policyId: record.policyId,
    policyVersion: record.version,
    policyHash: record.policyHash,
    requirements: overlay.logic.requirements,
    obligations: overlay.logic.obligations,
    binding: overlay.logic.binding,
    context: input.context,
    profileId: profile.profile_id,
    profileFlags: overlay.flags
  };
};
