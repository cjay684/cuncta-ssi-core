import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const exists = await knex.schema.hasTable("command_center_audit_events");
  if (!exists) return;
  await knex.raw(`
    CREATE INDEX IF NOT EXISTS command_center_audit_events_subject_created_desc_idx
    ON command_center_audit_events (subject_hash, created_at DESC)
  `);
  await knex.raw(`
    CREATE INDEX IF NOT EXISTS command_center_audit_events_created_idx
    ON command_center_audit_events (created_at)
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(`
    DROP INDEX IF EXISTS command_center_audit_events_subject_created_desc_idx
  `);
  await knex.raw(`
    DROP INDEX IF EXISTS command_center_audit_events_created_idx
  `);
}
