import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("policies", (table) => {
    table.text("policy_hash");
    table.text("policy_signature");
  });

  await knex.schema.alterTable("credential_types", (table) => {
    table.text("catalog_hash");
    table.text("catalog_signature");
  });

  await knex.schema.createTable("issuer_keys", (table) => {
    table.text("kid").primary();
    table.jsonb("public_jwk").notNullable();
    table.jsonb("private_jwk");
    table.text("status").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
  await knex.schema.alterTable("issuer_keys", (table) => {
    table.index(["status"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("issuer_keys", (table) => {
    table.dropIndex(["status"]);
  });
  await knex.schema.dropTableIfExists("issuer_keys");

  await knex.schema.alterTable("credential_types", (table) => {
    table.dropColumn("catalog_signature");
    table.dropColumn("catalog_hash");
  });

  await knex.schema.alterTable("policies", (table) => {
    table.dropColumn("policy_signature");
    table.dropColumn("policy_hash");
  });
}
