import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const vct = "age_credential_v1";
  const existing = await knex("credential_types").where({ vct }).first();
  if (existing) return;
  await knex("credential_types").insert({
    vct,
    json_schema: JSON.stringify({
      type: "object",
      properties: {
        dob_commitment: { type: "string" },
        commitment_scheme_version: { type: "string" }
      },
      required: ["dob_commitment", "commitment_scheme_version"],
      additionalProperties: false
    }),
    sd_defaults: JSON.stringify(["dob_commitment", "commitment_scheme_version"]),
    display: JSON.stringify({ title: "Age credential (ZK-ready)" }),
    purpose_limits: JSON.stringify({ actions: ["dating_enter", "dating_age_gate"] }),
    presentation_templates: JSON.stringify({
      required_disclosures: ["dob_commitment", "commitment_scheme_version"]
    }),
    revocation_config: JSON.stringify({
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex("credential_types").where({ vct: "age_credential_v1" }).del();
}

