import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  // Backward-compat for developer DBs created before `credential_types.schema` existed.
  // This migration seeds legacy ZK-age types; ensure the column exists so migrations don't fail mid-flight.
  const hasSchemaColumn = await knex.schema.hasColumn("credential_types", "schema");
  if (!hasSchemaColumn) {
    await knex.schema.table("credential_types", (table) => {
      table.text("schema");
    });
  }
  const hasJsonSchemaColumn = await knex.schema.hasColumn("credential_types", "json_schema");
  const hasRevocationConfigColumn = await knex.schema.hasColumn(
    "credential_types",
    "revocation_config"
  );

  await knex.schema.createTable("zk_age_groups", (table) => {
    table.text("group_id").primary();
    table.integer("merkle_depth").notNullable();
    table.text("root").notNullable();
    table.integer("member_count").notNullable().defaultTo(0);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("zk_age_group_members", (table) => {
    table.text("member_id").primary();
    table.text("group_id").notNullable().index();
    // Commitment is a field element encoded as a decimal string.
    table.text("identity_commitment").notNullable().index();
    // Linkable only with deployment pepper; enables DSR erase.
    table.text("subject_did_hash").notNullable().index();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.unique(["group_id", "identity_commitment"]);
  });

  // Seed credential type for the ZK age credential configuration.
  const existing = await knex("credential_types").where({ vct: "cuncta.zk.age.v1" }).first();
  if (!existing) {
    const jsonSchema = JSON.stringify({
      type: "object",
      properties: {
        predicate: { type: "string" },
        groupId: { type: "string" },
        merkleDepth: { type: "number" },
        identityCommitment: { type: "string" }
      },
      required: ["predicate", "groupId", "merkleDepth", "identityCommitment"]
    });
    const insertRow: Record<string, unknown> = {
      vct: "cuncta.zk.age.v1",
      display: JSON.stringify({ name: "Age predicate credential (ZK)" }),
      sd_defaults: JSON.stringify([]),
      purpose_limits: JSON.stringify({}),
      presentation_templates: JSON.stringify({})
    };
    // Newer schema: `json_schema` is required; older schema used `schema`.
    if (hasJsonSchemaColumn) insertRow.json_schema = jsonSchema;
    insertRow.schema = jsonSchema;
    if (hasRevocationConfigColumn) {
      // Align with the platform's default revocation posture if the column exists.
      insertRow.revocation_config = JSON.stringify({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048
      });
    }
    await knex("credential_types").insert(insertRow);
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex("credential_types").where({ vct: "cuncta.zk.age.v1" }).del();
  await knex.schema.dropTableIfExists("zk_age_group_members");
  await knex.schema.dropTableIfExists("zk_age_groups");
}
