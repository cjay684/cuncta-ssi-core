import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("verification_challenges", (table) => {
    table.text("policy_id");
    table.integer("policy_version");
    table.text("policy_hash");
    table.index(["policy_id", "policy_version"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("verification_challenges", (table) => {
    table.dropIndex(["policy_id", "policy_version"]);
    table.dropColumn("policy_hash");
    table.dropColumn("policy_version");
    table.dropColumn("policy_id");
  });
}
