import { Knex } from "knex";

const toJson = (value: unknown) => JSON.stringify(value);

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("obligations_executions", (table) => {
    table.unique(["challenge_hash", "action_id", "policy_id", "policy_version", "decision"]);
  });

  await knex.schema.alterTable("aura_issuance_queue", (table) => {
    table.timestamp("issued_at", { useTz: true });
    table.text("issuance_event_id");
    table.text("credential_fingerprint");
    table.text("error_code");
  });

  const updateRule = async (ruleId: string, overrides: Record<string, unknown>) => {
    const row = await knex("aura_rules").where({ rule_id: ruleId }).first();
    if (!row) return;
    const raw = row.rule_logic;
    const logic = typeof raw === "string" ? (JSON.parse(raw) as Record<string, unknown>) : raw;
    const merged = { ...logic, ...overrides };
    await knex("aura_rules")
      .where({ rule_id: ruleId })
      .update({ rule_logic: toJson(merged), updated_at: new Date().toISOString() });
  };

  await updateRule("marketplace.seller_good_standing.v1", {
    window_seconds: 30 * 24 * 60 * 60,
    per_counterparty_cap: 5,
    per_counterparty_decay_exponent: 0.5,
    diversity_min: 5,
    collusion_cluster_threshold: 0.6,
    collusion_multiplier: 0.7
  });

  await updateRule("marketplace.trusted_seller_tier.v1", {
    window_seconds: 30 * 24 * 60 * 60,
    per_counterparty_cap: 5,
    per_counterparty_decay_exponent: 0.5,
    diversity_min: 6,
    collusion_cluster_threshold: 0.6,
    collusion_multiplier: 0.7
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable("aura_issuance_queue", (table) => {
    table.dropColumn("issued_at");
    table.dropColumn("issuance_event_id");
    table.dropColumn("credential_fingerprint");
    table.dropColumn("error_code");
  });
  await knex.schema.alterTable("obligations_executions", (table) => {
    table.dropUnique(["challenge_hash", "action_id", "policy_id", "policy_version", "decision"]);
  });
}
