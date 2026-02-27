import type { DbClient } from "@cuncta/db";
import { PolicyLogicSchema } from "./policy/evaluate.js";

// Baseline policy data must exist "out of the box" even if the DB was pre-provisioned,
// partially migrated, or had seed rows deleted. Migrations are one-time; this is idempotent.
export const ensureBaselinePolicies = async (db: DbClient) => {
  const now = new Date().toISOString();

  const ensureAction = async (actionId: string, description: string) => {
    const existing = await db("actions").where({ action_id: actionId }).first();
    if (existing) return;
    await db("actions").insert({
      action_id: actionId,
      description,
      created_at: now,
      updated_at: now
    });
  };

  const upsertPolicy = async (policyId: string, actionId: string, logic: unknown) => {
    // Ensure logic is structurally valid (fail fast / actionable startup failure).
    const normalized = PolicyLogicSchema.parse(logic);
    const existing = await db("policies").where({ policy_id: policyId }).first();
    if (existing) {
      await db("policies")
        .where({ policy_id: policyId })
        .update({
          action_id: actionId,
          version: 1,
          enabled: true,
          logic: JSON.stringify(normalized),
          updated_at: now
        });
      return;
    }
    await db("policies").insert({
      policy_id: policyId,
      action_id: actionId,
      version: 1,
      enabled: true,
      logic: JSON.stringify(normalized),
      created_at: now,
      updated_at: now
    });
  };

  // ZK age gate policies (used by OID4VP `dating_enter` in the integration harness).
  await ensureAction("dating_age_gate", "Dating age gate entry");
  await ensureAction("dating_enter", "Dating enter action");

  const datingLogic = {
    binding: { mode: "kb-jwt", require: true },
    requirements: [
      {
        vct: "age_credential_v1",
        issuer: { mode: "env", env: "ISSUER_DID" },
        formats: ["dc+sd-jwt"],
        zk_predicates: [{ id: "age_gte_v1", params: { min_age: 18 } }],
        disclosures: ["dob_commitment", "commitment_scheme_version"],
        predicates: [],
        revocation: { required: true }
      }
    ],
    obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
  };

  await upsertPolicy("dating_age_gate.v1", "dating_age_gate", datingLogic);
  await upsertPolicy("dating_enter.v1", "dating_enter", datingLogic);
};
