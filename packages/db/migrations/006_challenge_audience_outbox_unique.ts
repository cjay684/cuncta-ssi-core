import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("verification_challenges", (table) => {
    table.text("audience");
  });

  await knex.schema.alterTable("anchor_outbox", (table) => {
    table.unique(["payload_hash"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("anchor_outbox", (table) => {
    table.dropUnique(["payload_hash"]);
  });

  await knex.schema.alterTable("verification_challenges", (table) => {
    table.dropColumn("audience");
  });
}
