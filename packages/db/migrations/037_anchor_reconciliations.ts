import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("anchor_reconciliations", (table) => {
    table.uuid("id").primary();
    table.text("payload_hash").notNullable().index();
    table.text("topic_id").notNullable();
    table.bigInteger("sequence_number").notNullable();
    table.text("consensus_timestamp").notNullable();
    table.timestamp("verified_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("status").notNullable();
    table.text("reason");
    table.text("mirror_message_hash");
    table.jsonb("mirror_response_meta");
    table.integer("attempts").notNullable().defaultTo(0);
    table.timestamp("last_attempt_at", { useTz: true });

    table.unique(["topic_id", "sequence_number"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("anchor_reconciliations");
}

