import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("sponsor_budget_daily", (table) => {
    table.date("day").primary();
    table.integer("did_creates_count").notNullable().defaultTo(0);
    table.integer("issues_count").notNullable().defaultTo(0);
    table.integer("anchors_count").notNullable().defaultTo(0);
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("sponsor_budget_daily");
}
