import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const hasPurgePending = await knex.schema.hasColumn("social_media_assets", "purge_pending");
  const hasLastPurgeAttemptAt = await knex.schema.hasColumn(
    "social_media_assets",
    "last_purge_attempt_at"
  );
  const hasPurgeAttemptCount = await knex.schema.hasColumn(
    "social_media_assets",
    "purge_attempt_count"
  );
  await knex.schema.alterTable("social_media_assets", (table) => {
    if (!hasPurgePending) {
      table.boolean("purge_pending").notNullable().defaultTo(false);
    }
    if (!hasLastPurgeAttemptAt) {
      table.timestamp("last_purge_attempt_at", { useTz: true }).nullable();
    }
    if (!hasPurgeAttemptCount) {
      table.integer("purge_attempt_count").notNullable().defaultTo(0);
    }
  });
  await knex.raw(
    'create index if not exists "social_media_assets_purge_pending_idx" on "social_media_assets" ("purge_pending", "last_purge_attempt_at")'
  );
}

export async function down(knex: Knex): Promise<void> {
  const hasPurgePending = await knex.schema.hasColumn("social_media_assets", "purge_pending");
  const hasLastPurgeAttemptAt = await knex.schema.hasColumn(
    "social_media_assets",
    "last_purge_attempt_at"
  );
  const hasPurgeAttemptCount = await knex.schema.hasColumn(
    "social_media_assets",
    "purge_attempt_count"
  );
  await knex.raw('drop index if exists "social_media_assets_purge_pending_idx"');
  await knex.schema.alterTable("social_media_assets", (table) => {
    if (hasPurgePending) table.dropColumn("purge_pending");
    if (hasLastPurgeAttemptAt) table.dropColumn("last_purge_attempt_at");
    if (hasPurgeAttemptCount) table.dropColumn("purge_attempt_count");
  });
}
