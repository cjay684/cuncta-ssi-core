import { Knex } from "knex";

const toJson = (value: unknown) => JSON.stringify(value);

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("obligations_executions", (table) => {
    table.text("id").primary();
    table.text("action_id").notNullable();
    table.text("policy_id").notNullable();
    table.integer("policy_version").notNullable();
    table.text("decision").notNullable();
    table.text("subject_did_hash").notNullable();
    table.text("token_hash").notNullable();
    table.text("challenge_hash").notNullable();
    table.text("obligations_hash").notNullable();
    table.timestamp("executed_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("anchor_payload_hash").notNullable();
    table.text("status").notNullable().defaultTo("PENDING");
    table.text("error_code");
    table.unique(["challenge_hash", "policy_id", "policy_version", "decision", "obligations_hash"]);
    table.index(["action_id", "policy_id", "policy_version"]);
  });

  await knex.schema.createTable("obligation_events", (table) => {
    table.bigIncrements("id").primary();
    table.text("action_id").notNullable();
    table.text("event_type").notNullable();
    table.text("subject_did_hash").notNullable();
    table.text("token_hash").notNullable();
    table.text("challenge_hash").notNullable();
    table.text("event_hash").notNullable().unique();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["action_id", "subject_did_hash", "created_at"]);
  });

  await knex.schema.createTable("aura_signals", (table) => {
    table.bigIncrements("id").primary();
    table.text("subject_did_hash").notNullable();
    table.text("domain").notNullable();
    table.text("signal").notNullable();
    table.integer("weight").notNullable().defaultTo(1);
    table.text("counterparty_did_hash");
    table.text("event_hash").notNullable().unique();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("processed_at", { useTz: true });
    table.text("anchored_payload_hash");
    table.index(["subject_did_hash", "domain", "created_at"]);
  });

  await knex.schema.createTable("aura_rules", (table) => {
    table.text("rule_id").primary();
    table.text("domain").notNullable();
    table.text("output_vct").notNullable();
    table.jsonb("rule_logic").notNullable();
    table.boolean("enabled").notNullable().defaultTo(true);
    table.integer("version").notNullable().defaultTo(1);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["domain", "enabled"]);
  });

  await knex.schema.createTable("aura_state", (table) => {
    table.text("subject_did_hash").notNullable();
    table.text("domain").notNullable();
    table.jsonb("state").notNullable().defaultTo("{}");
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["subject_did_hash", "domain"]);
  });

  await knex.schema.createTable("aura_issuance_queue", (table) => {
    table.text("queue_id").primary();
    table.text("rule_id").notNullable();
    table.text("subject_did_hash").notNullable();
    table.text("domain").notNullable();
    table.text("output_vct").notNullable();
    table.text("reason_hash").notNullable();
    table.text("status").notNullable().defaultTo("PENDING");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.unique(["rule_id", "subject_did_hash", "reason_hash"]);
    table.index(["status", "output_vct"]);
  });

  await knex("credential_types").insert([
    {
      vct: "cuncta.marketplace.trusted_seller_tier",
      json_schema: toJson({
        type: "object",
        properties: {
          trusted_seller_tier: { type: "string", enum: ["silver", "gold"] },
          domain: { type: "string" },
          as_of: { type: "string", format: "date-time" }
        },
        required: ["trusted_seller_tier", "domain", "as_of"],
        additionalProperties: false
      }),
      sd_defaults: toJson(["trusted_seller_tier"]),
      display: toJson({
        title: "Trusted Seller Tier",
        claims: [
          { path: "trusted_seller_tier", label: "Tier" },
          { path: "domain", label: "Domain" }
        ]
      }),
      purpose_limits: toJson({ actions: ["marketplace.list_high_value"] }),
      presentation_templates: toJson({ required_disclosures: ["trusted_seller_tier"] }),
      revocation_config: toJson({
        statusPurpose: "revocation",
        statusListId: "default",
        bitstringSize: 2048
      })
    }
  ]);

  await knex("actions").insert([
    {
      action_id: "marketplace.list_high_value",
      description: "List a high-value item in the marketplace"
    }
  ]);

  await knex("policies").insert([
    {
      policy_id: "marketplace.list_high_value.v1",
      action_id: "marketplace.list_high_value",
      version: 1,
      enabled: true,
      logic: toJson({
        binding: { mode: "kb-jwt", require: true },
        requirements: [
          {
            vct: "cuncta.marketplace.trusted_seller_tier",
            issuer: { mode: "env", env: "ISSUER_DID" },
            disclosures: ["trusted_seller_tier"],
            predicates: [
              { path: "trusted_seller_tier", op: "in", value: ["silver", "gold"] },
              { path: "domain", op: "eq", value: "marketplace" }
            ],
            revocation: { required: true }
          }
        ],
        obligations: [
          { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
          { type: "EMIT_EVENT", event: "MARKETPLACE_LIST_HIGH_VALUE", when: "ALWAYS" },
          {
            type: "AURA_SIGNAL",
            signal: "marketplace.listing_success",
            weight: 2,
            when: "ON_ALLOW"
          }
        ]
      })
    }
  ]);

  const policy = await knex("policies").where({ policy_id: "marketplace.list_item.v1" }).first();
  if (policy) {
    const logicRaw = policy.logic;
    const logic =
      typeof logicRaw === "string" ? (JSON.parse(logicRaw) as Record<string, unknown>) : logicRaw;
    logic.obligations = [
      { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
      { type: "EMIT_EVENT", event: "MARKETPLACE_LIST_ITEM_ATTEMPT", when: "ALWAYS" },
      { type: "AURA_SIGNAL", signal: "marketplace.listing_success", weight: 1, when: "ON_ALLOW" }
    ];
    await knex("policies")
      .where({ policy_id: "marketplace.list_item.v1" })
      .update({
        logic: JSON.stringify(logic),
        updated_at: new Date().toISOString()
      });
  }

  await knex("aura_rules").insert([
    {
      rule_id: "marketplace.seller_good_standing.v1",
      domain: "marketplace",
      output_vct: "cuncta.marketplace.seller_good_standing",
      version: 1,
      rule_logic: toJson({
        purpose: "Capability to list items in the marketplace (good standing entitlement)",
        window_days: 30,
        signals: ["marketplace.listing_success"],
        score: { min_silver: 5, min_gold: 12 },
        diversity: { min_for_silver: 5, min_for_gold: 12 },
        anti_collusion: { top2_ratio: 0.6, multiplier: 0.7 },
        min_tier: "bronze",
        output: {
          claims: {
            seller_good_standing: true,
            domain: "{domain}",
            tier: "{tier}",
            as_of: "{now}"
          }
        }
      })
    },
    {
      rule_id: "marketplace.trusted_seller_tier.v1",
      domain: "marketplace",
      output_vct: "cuncta.marketplace.trusted_seller_tier",
      version: 1,
      rule_logic: toJson({
        purpose:
          "Capability to list high-value items in the marketplace (trusted seller tier entitlement)",
        window_days: 30,
        signals: ["marketplace.listing_success"],
        score: { min_silver: 8, min_gold: 16 },
        diversity: { min_for_silver: 6, min_for_gold: 14 },
        anti_collusion: { top2_ratio: 0.6, multiplier: 0.7 },
        min_tier: "silver",
        output: {
          claims: {
            trusted_seller_tier: "{tier}",
            domain: "{domain}",
            as_of: "{now}"
          }
        }
      })
    }
  ]);
}

export async function down(knex: Knex): Promise<void> {
  await knex("aura_rules")
    .whereIn("rule_id", [
      "marketplace.seller_good_standing.v1",
      "marketplace.trusted_seller_tier.v1"
    ])
    .del();
  await knex("policies").where({ policy_id: "marketplace.list_high_value.v1" }).del();
  await knex("actions").where({ action_id: "marketplace.list_high_value" }).del();
  await knex("credential_types").where({ vct: "cuncta.marketplace.trusted_seller_tier" }).del();

  await knex.schema.dropTableIfExists("aura_issuance_queue");
  await knex.schema.dropTableIfExists("aura_state");
  await knex.schema.dropTableIfExists("aura_rules");
  await knex.schema.dropTableIfExists("aura_signals");
  await knex.schema.dropTableIfExists("obligation_events");
  await knex.schema.dropTableIfExists("obligations_executions");
}
