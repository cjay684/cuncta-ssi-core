import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  const hasPreauth = await knex.schema.hasTable("oid4vci_preauth_codes");
  if (hasPreauth) {
    const hasScopeJson = await knex.schema.hasColumn("oid4vci_preauth_codes", "scope_json");
    const hasScopeHash = await knex.schema.hasColumn("oid4vci_preauth_codes", "scope_hash");
    if (!hasScopeJson || !hasScopeHash) {
      await knex.schema.alterTable("oid4vci_preauth_codes", (table) => {
        if (!hasScopeJson) table.jsonb("scope_json");
        if (!hasScopeHash) table.text("scope_hash");
      });
    }
    // Best-effort index; safe if already exists.
    await knex.schema
      .alterTable("oid4vci_preauth_codes", (table) => {
        table.index(["scope_hash"], "oid4vci_preauth_scope_hash_idx");
      })
      .catch(() => undefined);
  }

  const hasChallenges = await knex.schema.hasTable("oid4vci_offer_challenges");
  if (!hasChallenges) {
    await knex.schema.createTable("oid4vci_offer_challenges", (table) => {
      table.text("nonce_hash").primary();
      table.timestamp("expires_at", { useTz: true }).notNullable();
      table.timestamp("consumed_at", { useTz: true });
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.index(["expires_at"]);
      table.index(["consumed_at"]);
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("oid4vci_offer_challenges");
  const hasPreauth = await knex.schema.hasTable("oid4vci_preauth_codes");
  if (hasPreauth) {
    const hasScopeJson = await knex.schema.hasColumn("oid4vci_preauth_codes", "scope_json");
    const hasScopeHash = await knex.schema.hasColumn("oid4vci_preauth_codes", "scope_hash");
    await knex.schema.alterTable("oid4vci_preauth_codes", (table) => {
      if (hasScopeJson) table.dropColumn("scope_json");
      if (hasScopeHash) table.dropColumn("scope_hash");
    });
  }
}
