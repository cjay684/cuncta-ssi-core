import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("anchor_outbox");
  await knex.schema.dropTableIfExists("status_lists");
  await knex.schema.dropTableIfExists("issued_credentials");
  await knex.schema.dropTableIfExists("credential_catalog");
  await knex.schema.dropTableIfExists("policies");

  await knex.schema.createTable("credential_types", (table) => {
    table.text("vct").primary();
    table.jsonb("json_schema").notNullable();
    table.jsonb("sd_defaults").notNullable();
    table.jsonb("display").notNullable();
    table.jsonb("purpose_limits").notNullable();
    table.jsonb("presentation_templates").notNullable();
    table.jsonb("revocation_config").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("actions", (table) => {
    table.text("action_id").primary();
    table.text("description").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("policies", (table) => {
    table.text("policy_id").primary();
    table
      .text("action_id")
      .notNullable()
      .references("action_id")
      .inTable("actions")
      .onDelete("CASCADE");
    table.integer("version").notNullable();
    table.boolean("enabled").notNullable().defaultTo(true);
    table.jsonb("logic").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("status_lists", (table) => {
    table.text("status_list_id").primary();
    table.text("purpose").notNullable();
    table.integer("bitstring_size").notNullable();
    table.integer("current_version").notNullable().defaultTo(1);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("status_list_versions", (table) => {
    table
      .text("status_list_id")
      .notNullable()
      .references("status_list_id")
      .inTable("status_lists")
      .onDelete("CASCADE");
    table.integer("version").notNullable();
    table.text("bitstring_base64").notNullable();
    table.timestamp("published_at", { useTz: true });
    table.text("anchor_payload_hash");
    table.primary(["status_list_id", "version"]);
  });

  await knex.schema.createTable("issuance_events", (table) => {
    table.text("event_id").primary();
    table.text("vct").notNullable();
    table.text("subject_did_hash");
    table.text("credential_fingerprint").notNullable();
    table.text("status_list_id").notNullable();
    table.integer("status_index").notNullable();
    table.timestamp("issued_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("anchor_outbox", (table) => {
    table.text("outbox_id").primary();
    table.text("event_type").notNullable();
    table.text("payload_hash").notNullable();
    table.jsonb("payload_meta").notNullable().defaultTo("{}");
    table.text("status").notNullable().defaultTo("PENDING");
    table.integer("attempts").notNullable().defaultTo(0);
    table.timestamp("next_retry_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("anchor_receipts", (table) => {
    table.text("payload_hash").primary();
    table.text("topic_id").notNullable();
    table.text("sequence_number").notNullable();
    table.text("consensus_timestamp").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  const toJson = (value: unknown) => JSON.stringify(value);

  await knex("credential_types").insert([
    {
      vct: "cuncta.marketplace.seller_good_standing",
      json_schema: toJson({
        type: "object",
        properties: {
          seller_good_standing: { type: "boolean" },
          domain: { type: "string" },
          as_of: { type: "string", format: "date-time" },
          tier: { type: "string", enum: ["bronze", "silver", "gold"] }
        },
        required: ["seller_good_standing", "domain", "as_of", "tier"],
        additionalProperties: false
      }),
      sd_defaults: toJson(["seller_good_standing"]),
      display: toJson({
        title: "Seller Good Standing",
        claims: [
          { path: "seller_good_standing", label: "Good standing" },
          { path: "tier", label: "Tier" }
        ]
      }),
      purpose_limits: toJson({ actions: ["marketplace.list_item"] }),
      presentation_templates: toJson({
        required_disclosures: ["seller_good_standing", "tier"]
      }),
      revocation_config: toJson({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048
      })
    }
  ]);

  await knex("actions").insert([
    {
      action_id: "marketplace.list_item",
      description: "List an item in the marketplace"
    }
  ]);

  await knex("policies").insert([
    {
      policy_id: "marketplace.list_item.v1",
      action_id: "marketplace.list_item",
      version: 1,
      enabled: true,
      logic: toJson({
        binding: { mode: "kb-jwt", require: true },
        requirements: [
          {
            vct: "cuncta.marketplace.seller_good_standing",
            issuer: { mode: "env", env: "ISSUER_DID" },
            disclosures: ["seller_good_standing", "tier"],
            predicates: [
              { path: "seller_good_standing", op: "eq", value: true },
              { path: "domain", op: "eq", value: "marketplace" }
            ],
            revocation: { required: true }
          }
        ]
      })
    }
  ]);
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("anchor_receipts");
  await knex.schema.dropTableIfExists("anchor_outbox");
  await knex.schema.dropTableIfExists("issuance_events");
  await knex.schema.dropTableIfExists("status_list_versions");
  await knex.schema.dropTableIfExists("status_lists");
  await knex.schema.dropTableIfExists("policies");
  await knex.schema.dropTableIfExists("actions");
  await knex.schema.dropTableIfExists("credential_types");
}
