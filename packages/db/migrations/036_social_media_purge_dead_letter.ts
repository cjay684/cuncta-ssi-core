import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const hasDeadLetteredAt = await knex.schema.hasColumn(
    "social_media_assets",
    "purge_dead_lettered_at"
  );
  const hasDeadLetterReason = await knex.schema.hasColumn(
    "social_media_assets",
    "purge_dead_letter_reason"
  );
  await knex.schema.alterTable("social_media_assets", (table) => {
    if (!hasDeadLetteredAt) {
      table.timestamp("purge_dead_lettered_at", { useTz: true }).nullable();
    }
    if (!hasDeadLetterReason) {
      table.text("purge_dead_letter_reason").nullable();
    }
  });
  await knex.raw(
    'create index if not exists "social_media_assets_purge_dead_lettered_idx" on "social_media_assets" ("purge_dead_lettered_at")'
  );
}

export async function down(knex: Knex): Promise<void> {
  const hasDeadLetteredAt = await knex.schema.hasColumn(
    "social_media_assets",
    "purge_dead_lettered_at"
  );
  const hasDeadLetterReason = await knex.schema.hasColumn(
    "social_media_assets",
    "purge_dead_letter_reason"
  );
  await knex.raw('drop index if exists "social_media_assets_purge_dead_lettered_idx"');
  await knex.schema.alterTable("social_media_assets", (table) => {
    if (hasDeadLetteredAt) table.dropColumn("purge_dead_lettered_at");
    if (hasDeadLetterReason) table.dropColumn("purge_dead_letter_reason");
  });
}
