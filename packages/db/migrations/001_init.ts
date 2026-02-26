import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("credential_catalog", (table) => {
    table.text("vct").primary();
    table.text("lane").notNullable();
    table.text("name").notNullable();
    table.text("description").notNullable();
    table.jsonb("json_schema").notNullable();
    table.jsonb("display").notNullable();
    table.jsonb("sd_disclosure_defaults").notNullable();
    table.jsonb("presentation_template").notNullable();
    table.jsonb("revocation").notNullable();
    table.jsonb("purpose_limits").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("policies", (table) => {
    table.text("action").primary();
    table.jsonb("requirements").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("status_lists", (table) => {
    table.text("list_id").primary();
    table.integer("length").notNullable();
    table.text("bitstring").notNullable();
    table.integer("next_index").notNullable().defaultTo(0);
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("last_status_list_vc_hash");
    table.text("last_anchor_tx_id");
    table.boolean("last_anchor_failed");
  });

  await knex.schema.createTable("issued_credentials", (table) => {
    table.text("credential_id").primary();
    table.text("vct").notNullable();
    table.text("subject_did_hash").notNullable();
    table.timestamp("issued_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("status_list_id").notNullable();
    table.integer("status_list_index").notNullable();
    table.text("sd_jwt_hash").notNullable();
    table.text("anchor_status").notNullable().defaultTo("pending");
    table.text("anchor_tx_id");
    table.text("anchor_last_error");
  });

  await knex.schema.createTable("anchor_outbox", (table) => {
    table.text("id").primary();
    table.text("idempotency_key").notNullable().unique();
    table.text("kind").notNullable();
    table.text("sha256").notNullable();
    table.jsonb("metadata").notNullable().defaultTo("{}");
    table.text("status").notNullable().defaultTo("pending");
    table.integer("attempt_count").notNullable().defaultTo(0);
    table.timestamp("next_attempt_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("last_error");
    table.text("tx_id");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("reputation_events", (table) => {
    table.bigIncrements("id").primary();
    table.text("actor_pseudonym").notNullable();
    table.text("counterparty_pseudonym").notNullable();
    table.text("domain").notNullable();
    table.text("event_type").notNullable();
    table.timestamp("timestamp", { useTz: true }).notNullable();
    table.text("evidence_hash");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("audit_logs", (table) => {
    table.bigIncrements("id").primary();
    table.text("event_type").notNullable();
    table.text("entity_id");
    table.text("data_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  const toJson = (value: unknown) => JSON.stringify(value);

  await knex("credential_catalog").insert([
    {
      vct: "cuncta.age_over_18",
      lane: "sd-jwt-vc",
      name: "Age Over 18",
      description: "Attests that the holder is over 18 years old.",
      json_schema: toJson({
        type: "object",
        properties: { age_over_18: { type: "boolean" } },
        required: ["age_over_18"],
        additionalProperties: false
      }),
      display: toJson({
        title: "Age 18+",
        claims: [{ path: "age_over_18", label: "Over 18" }]
      }),
      sd_disclosure_defaults: toJson(["age_over_18"]),
      presentation_template: toJson({ required_disclosures: ["age_over_18"] }),
      revocation: toJson({ statusPurpose: "revocation", defaultListId: "default" }),
      purpose_limits: toJson({ actions: ["dating_age_gate", "dating_enter"] })
    },
    {
      vct: "cuncta.marketplace.seller_good_standing",
      lane: "sd-jwt-vc",
      name: "Marketplace Seller Good Standing",
      description: "Domain-scoped standing for marketplace sellers.",
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
      display: toJson({
        title: "Seller Good Standing",
        claims: [
          { path: "tier", label: "Tier" },
          { path: "as_of", label: "As of" }
        ]
      }),
      sd_disclosure_defaults: toJson(["seller_good_standing", "domain", "as_of", "tier"]),
      presentation_template: toJson({ required_disclosures: ["seller_good_standing", "tier"] }),
      revocation: toJson({ statusPurpose: "revocation", defaultListId: "default" }),
      purpose_limits: toJson({ actions: ["marketplace.list.high_value"] })
    }
  ]);

  await knex("policies").insert([
    {
      action: "dating_age_gate",
      requirements: toJson([
        {
          vct: "cuncta.age_over_18",
          accepted_lanes: ["sd-jwt-vc"],
          predicates: [{ path: "age_over_18", op: "eq", value: true }],
          reason: "Age gate requirement",
          remediation: "Present an age_over_18 credential"
        }
      ])
    },
    {
      action: "dating_enter",
      requirements: toJson([
        {
          vct: "cuncta.age_over_18",
          accepted_lanes: ["sd-jwt-vc"],
          predicates: [{ path: "age_over_18", op: "eq", value: true }],
          reason: "Age gate requirement",
          remediation: "Present an age_over_18 credential"
        }
      ])
    },
    {
      action: "marketplace.list.high_value",
      requirements: toJson([
        {
          vct: "cuncta.marketplace.seller_good_standing",
          accepted_lanes: ["sd-jwt-vc"],
          predicates: [
            { path: "seller_good_standing", op: "eq", value: true },
            { path: "domain", op: "eq", value: "marketplace" },
            { path: "tier", op: "gte", value: "silver" }
          ],
          reason: "Seller must be in good standing",
          remediation: "Earn seller_good_standing tier silver or higher"
        }
      ])
    }
  ]);
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("audit_logs");
  await knex.schema.dropTableIfExists("reputation_events");
  await knex.schema.dropTableIfExists("anchor_outbox");
  await knex.schema.dropTableIfExists("issued_credentials");
  await knex.schema.dropTableIfExists("status_lists");
  await knex.schema.dropTableIfExists("policies");
  await knex.schema.dropTableIfExists("credential_catalog");
}
