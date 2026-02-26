import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const hasTable = await knex.schema.hasTable("social_realtime_events");
  if (!hasTable) return;
  const hasCursor = await knex.schema.hasColumn("social_realtime_events", "event_cursor");
  if (!hasCursor) {
    await knex.schema.alterTable("social_realtime_events", (table) => {
      table.bigInteger("event_cursor");
    });
  }
  await knex.raw(`
    CREATE SEQUENCE IF NOT EXISTS social_realtime_events_event_cursor_seq
  `);
  await knex.raw(`
    ALTER TABLE social_realtime_events
    ALTER COLUMN event_cursor SET DEFAULT nextval('social_realtime_events_event_cursor_seq')
  `);
  await knex.raw(`
    UPDATE social_realtime_events
    SET event_cursor = nextval('social_realtime_events_event_cursor_seq')
    WHERE event_cursor IS NULL
  `);
  await knex.raw(`
    ALTER TABLE social_realtime_events
    ALTER COLUMN event_cursor SET NOT NULL
  `);
  await knex.raw(`
    CREATE UNIQUE INDEX IF NOT EXISTS social_realtime_events_event_cursor_uq
    ON social_realtime_events(event_cursor)
  `);
  await knex.raw(`
    CREATE INDEX IF NOT EXISTS social_realtime_events_channel_space_cursor_idx
    ON social_realtime_events(channel, space_id, event_cursor)
  `);
}

export async function down(knex: Knex): Promise<void> {
  const hasTable = await knex.schema.hasTable("social_realtime_events");
  if (!hasTable) return;
  const hasCursor = await knex.schema.hasColumn("social_realtime_events", "event_cursor");
  if (!hasCursor) return;
  await knex.raw(`
    DROP INDEX IF EXISTS social_realtime_events_channel_space_cursor_idx
  `);
  await knex.raw(`
    DROP INDEX IF EXISTS social_realtime_events_event_cursor_uq
  `);
  await knex.schema.alterTable("social_realtime_events", (table) => {
    table.dropColumn("event_cursor");
  });
  await knex.raw(`
    DROP SEQUENCE IF EXISTS social_realtime_events_event_cursor_seq
  `);
}
