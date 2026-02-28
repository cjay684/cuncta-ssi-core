import { getDb } from "../db.js";

export const ensureIdentityVerifyPolicy = async () => {
  const db = await getDb();
  const actionId = "identity.verify";
  const policyId = "identity.verify.v1";

  const now = new Date().toISOString();
  await db("actions")
    .insert({
      action_id: actionId,
      description: "Verify holder identity capability",
      created_at: now,
      updated_at: now
    })
    .onConflict("action_id")
    .merge({ description: "Verify holder identity capability", updated_at: now });

  const logic = {
    binding: { mode: "kb-jwt", require: true },
    requirements: [
      {
        vct: "cuncta.age_over_18",
        issuer: { mode: "env", env: "ISSUER_DID" },
        disclosures: ["age_over_18"],
        predicates: [{ path: "age_over_18", op: "eq", value: true }],
        revocation: { required: true }
      }
    ]
  };

  await db("policies")
    .insert({
      policy_id: policyId,
      action_id: actionId,
      version: 1,
      enabled: true,
      logic,
      policy_hash: null,
      policy_signature: null,
      created_at: now,
      updated_at: now
    })
    .onConflict("policy_id")
    .merge({
      action_id: actionId,
      version: 1,
      enabled: true,
      logic,
      policy_hash: null,
      policy_signature: null,
      updated_at: now
    });
};
