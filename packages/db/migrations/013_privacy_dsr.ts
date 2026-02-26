import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("privacy_requests", (table) => {
    table.text("request_id").primary();
    table.text("did_hash").notNullable();
    table.text("nonce_hash").notNullable();
    table.text("audience").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["did_hash", "created_at"]);
    table.index(["expires_at"]);
  });

  await knex.schema.createTable("privacy_tokens", (table) => {
    table.text("token_hash").primary();
    table.text("did_hash").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["did_hash", "expires_at"]);
  });

  await knex.schema.createTable("privacy_restrictions", (table) => {
    table.text("did_hash").primary();
    table.timestamp("restricted_at", { useTz: true }).notNullable();
    table.text("reason_hash");
    table.index(["restricted_at"]);
  });

  await knex.schema.createTable("privacy_tombstones", (table) => {
    table.text("did_hash").primary();
    table.timestamp("erased_at", { useTz: true }).notNullable();
    table.index(["erased_at"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("privacy_tombstones");
  await knex.schema.dropTableIfExists("privacy_restrictions");
  await knex.schema.dropTableIfExists("privacy_tokens");
  await knex.schema.dropTableIfExists("privacy_requests");
}
