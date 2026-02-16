import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("sponsor_budget_events", (table) => {
    table.uuid("id").primary();
    table.date("day").notNullable();
    table.text("kind").notNullable();
    table.text("status").notNullable();
    table.text("request_id_hash");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["day", "kind", "status"], "sponsor_budget_events_day_kind_status_idx");
  });

  await knex.raw(`
    CREATE UNIQUE INDEX sponsor_budget_events_request_hash_uniq
    ON sponsor_budget_events (day, kind, request_id_hash)
    WHERE request_id_hash IS NOT NULL
  `);

  await knex.schema.createTable("policy_version_floor", (table) => {
    table.text("action_id").primary();
    table.integer("min_version").notNullable();
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("policy_version_floor");
  await knex.schema.dropTableIfExists("sponsor_budget_events");
}
