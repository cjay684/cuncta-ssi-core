import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const ensureAction = async (actionId: string, description: string) => {
    const existing = await knex("actions").where({ action_id: actionId }).first();
    if (!existing) {
      await knex("actions").insert({
        action_id: actionId,
        description,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    }
  };

  await ensureAction("dating_age_gate", "Dating age gate entry");
  await ensureAction("dating_enter", "Dating enter action");

  const upsertPolicy = async (policyId: string, actionId: string) => {
    const existing = await knex("policies").where({ policy_id: policyId }).first();
    const logic = {
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

    if (existing) {
      await knex("policies")
        .where({ policy_id: policyId })
        .update({
          action_id: actionId,
          version: 1,
          enabled: true,
          logic: JSON.stringify(logic),
          updated_at: new Date().toISOString()
        });
    } else {
      await knex("policies").insert({
        policy_id: policyId,
        action_id: actionId,
        version: 1,
        enabled: true,
        logic: JSON.stringify(logic),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    }
  };

  await upsertPolicy("dating_age_gate.v1", "dating_age_gate");
  await upsertPolicy("dating_enter.v1", "dating_enter");
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies").whereIn("policy_id", ["dating_age_gate.v1", "dating_enter.v1"]).del();
  await knex("actions").whereIn("action_id", ["dating_age_gate", "dating_enter"]).del();
}
