import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("anchor_outbox", (table) => {
    table.timestamp("processing_started_at", { useTz: true });
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("anchor_outbox", (table) => {
    table.dropColumn("processing_started_at");
  });
}
