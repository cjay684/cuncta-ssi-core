import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("privacy_requests", (table) => {
    table.text("did_hash_legacy");
    table.index(["did_hash_legacy", "created_at"]);
  });
  await knex.schema.alterTable("privacy_tokens", (table) => {
    table.text("did_hash_legacy");
    table.index(["did_hash_legacy", "expires_at"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("privacy_tokens", (table) => {
    table.dropIndex(["did_hash_legacy", "expires_at"]);
    table.dropColumn("did_hash_legacy");
  });
  await knex.schema.alterTable("privacy_requests", (table) => {
    table.dropIndex(["did_hash_legacy", "created_at"]);
    table.dropColumn("did_hash_legacy");
  });
}
