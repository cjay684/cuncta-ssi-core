import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const existing = await knex("credential_types").where({ vct: "cuncta.age_over_18" }).first();
  if (existing) {
    return;
  }

  const toJson = (value: unknown) => JSON.stringify(value);
  await knex("credential_types").insert({
    vct: "cuncta.age_over_18",
    json_schema: toJson({
      type: "object",
      properties: { age_over_18: { type: "boolean" } },
      required: ["age_over_18"],
      additionalProperties: false
    }),
    sd_defaults: toJson(["age_over_18"]),
    display: toJson({
      title: "Age 18+",
      claims: [{ path: "age_over_18", label: "Over 18" }]
    }),
    purpose_limits: toJson({ actions: ["dating_age_gate", "dating_enter"] }),
    presentation_templates: toJson({ required_disclosures: ["age_over_18"] }),
    revocation_config: toJson({
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex("credential_types").where({ vct: "cuncta.age_over_18" }).del();
}
