import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("audit_logs", (table) => {
    table.text("prev_hash");
    table.text("chain_hash");
  });

  await knex.schema.alterTable("aura_rules", (table) => {
    table.text("rule_signature");
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("audit_logs", (table) => {
    table.dropColumn("prev_hash");
    table.dropColumn("chain_hash");
  });

  await knex.schema.alterTable("aura_rules", (table) => {
    table.dropColumn("rule_signature");
  });
}
