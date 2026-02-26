import { Knex } from "knex";

const toJson = (value: unknown) => JSON.stringify(value);

export async function up(knex: Knex): Promise<void> {
  const actionId = "dev.aura.signal";
  const policyId = "dev.aura.signal.v1";

  const existingAction = await knex("actions").where({ action_id: actionId }).first();
  if (!existingAction) {
    await knex("actions").insert([
      {
        action_id: actionId,
        description: "Dev-only aura signal demo action"
      }
    ]);
  }

  const existingPolicy = await knex("policies").where({ policy_id: policyId }).first();
  if (!existingPolicy) {
    await knex("policies").insert([
      {
        policy_id: policyId,
        action_id: actionId,
        version: 1,
        enabled: true,
        logic: toJson({
          binding: { mode: "kb-jwt", require: true },
          requirements: [
            {
              vct: "cuncta.marketplace.seller_good_standing",
              issuer: { mode: "allowlist", allowed: ["*"] },
              disclosures: ["seller_good_standing", "tier", "domain"],
              predicates: [{ path: "seller_good_standing", op: "eq", value: true }],
              revocation: { required: true }
            }
          ],
          obligations: [
            { type: "EMIT_EVENT", event: "DEV_AURA_SIGNAL", when: "ALWAYS" },
            {
              type: "AURA_SIGNAL",
              signal: "marketplace.listing_success",
              weight: 1,
              when: "ON_ALLOW"
            }
          ]
        })
      }
    ]);
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies").where({ policy_id: "dev.aura.signal.v1" }).del();
  await knex("actions").where({ action_id: "dev.aura.signal" }).del();
}
