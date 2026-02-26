import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const hasSpaceId = await knex.schema.hasColumn("social_reports", "space_id");
  const hasTargetSpacePostId = await knex.schema.hasColumn(
    "social_reports",
    "target_space_post_id"
  );
  if (!hasSpaceId || !hasTargetSpacePostId) {
    await knex.schema.alterTable("social_reports", (table) => {
      if (!hasSpaceId) {
        table.uuid("space_id").references("space_id").inTable("social_spaces").onDelete("SET NULL");
      }
      if (!hasTargetSpacePostId) {
        table
          .uuid("target_space_post_id")
          .references("space_post_id")
          .inTable("social_space_posts")
          .onDelete("SET NULL");
      }
    });
  }

  const hasModerationCases = await knex.schema.hasTable("social_space_moderation_cases");
  if (!hasModerationCases) {
    await knex.schema.createTable("social_space_moderation_cases", (table) => {
      table.uuid("case_id").primary();
      table
        .uuid("space_id")
        .notNullable()
        .references("space_id")
        .inTable("social_spaces")
        .onDelete("CASCADE");
      table
        .uuid("report_id")
        .notNullable()
        .unique()
        .references("report_id")
        .inTable("social_reports")
        .onDelete("CASCADE");
      table.text("status").notNullable().defaultTo("OPEN");
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.index(
        ["space_id", "status", "created_at"],
        "social_space_moderation_cases_space_status_idx"
      );
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("social_space_moderation_cases");
}
