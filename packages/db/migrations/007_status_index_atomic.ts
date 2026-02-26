import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("status_lists", (table) => {
    table.integer("next_index").notNullable().defaultTo(0);
  });

  await knex.schema.alterTable("issuance_events", (table) => {
    table.unique(["status_list_id", "status_index"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("issuance_events", (table) => {
    table.dropUnique(["status_list_id", "status_index"]);
  });

  await knex.schema.alterTable("status_lists", (table) => {
    table.dropColumn("next_index");
  });
}
