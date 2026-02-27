import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  // OID4VCI: pre-authorized codes are bearer tokens; store only hashes + TTL + one-time consumption.
  await knex.schema.createTable("oid4vci_preauth_codes", (table) => {
    table.text("code_hash").primary();
    table.text("vct").notNullable();
    table.text("tx_code_hash");
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
    table.index(["vct", "created_at"]);
  });

  // OID4VCI: c_nonce replay prevention for proof-of-possession.
  await knex.schema.createTable("oid4vci_c_nonces", (table) => {
    table.text("nonce_hash").primary();
    table.text("token_jti_hash").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
    table.index(["token_jti_hash", "created_at"]);
  });

  // OID4VP: request object one-time semantics. Store only request hashes + TTL.
  await knex.schema.createTable("oid4vp_request_hashes", (table) => {
    table.text("request_hash").primary();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["expires_at"]);
    table.index(["consumed_at"]);
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("oid4vp_request_hashes");
  await knex.schema.dropTableIfExists("oid4vci_c_nonces");
  await knex.schema.dropTableIfExists("oid4vci_preauth_codes");
}
