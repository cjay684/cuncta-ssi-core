import { Knex } from "knex";

/**
 * NOTE:
 * This migration intentionally shares the "033_" prefix with another migration in this repository.
 * Knex tracks migrations by full filename, so this is safe once applied.
 * Do not rename this file after any environment has applied it, or migration history may diverge.
 */
export async function up(knex: Knex): Promise<void> {
  const exists = await knex.schema.hasTable("command_center_audit_events");
  if (exists) return;
  await knex.schema.createTable("command_center_audit_events", (table) => {
    table.uuid("id").primary();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("subject_hash").notNullable();
    table.text("event_type").notNullable();
    table.jsonb("payload_json").notNullable().defaultTo("{}");
    table.index(["event_type", "created_at"], "command_center_audit_events_type_created_idx");
    table.index(["subject_hash", "created_at"], "command_center_audit_events_subject_created_idx");
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("command_center_audit_events");
}
