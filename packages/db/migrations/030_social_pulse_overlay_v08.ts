import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("social_space_pulse_preferences", (table) => {
    table.uuid("space_id").notNullable();
    table.text("subject_hash").notNullable();
    table.boolean("enabled").notNullable().defaultTo(true);
    table.boolean("notify_hangouts").notNullable().defaultTo(true);
    table.boolean("notify_crews").notNullable().defaultTo(true);
    table.boolean("notify_challenges").notNullable().defaultTo(true);
    table.boolean("notify_rankings").notNullable().defaultTo(true);
    table.boolean("notify_streaks").notNullable().defaultTo(true);
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["space_id", "subject_hash"], {
      constraintName: "social_space_pulse_preferences_pk"
    });
    table.index(["space_id", "updated_at"], "social_space_pulse_preferences_space_updated_idx");
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("social_space_pulse_preferences");
}
