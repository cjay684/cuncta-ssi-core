import { Knex } from "knex";

const updatePurposeLimits = async (knex: Knex, vct: string, actions: string[]) => {
  const existing = await knex("credential_types").where({ vct }).first();
  if (!existing) return;
  await knex("credential_types").where({ vct }).update({
    purpose_limits: { actions },
    updated_at: new Date().toISOString()
  });
};

const upsertAuraRule = async (
  knex: Knex,
  input: {
    rule_id: string;
    domain: string;
    output_vct: string;
    version: number;
    rule_logic: unknown;
  }
) => {
  const now = new Date().toISOString();
  const existing = await knex("aura_rules").where({ rule_id: input.rule_id }).first();
  if (!existing) {
    await knex("aura_rules").insert({
      rule_id: input.rule_id,
      domain: input.domain,
      output_vct: input.output_vct,
      version: input.version,
      rule_logic: input.rule_logic,
      enabled: true,
      updated_at: now
    });
    return;
  }
  await knex("aura_rules").where({ rule_id: input.rule_id }).update({
    domain: input.domain,
    output_vct: input.output_vct,
    version: input.version,
    rule_logic: input.rule_logic,
    enabled: true,
    updated_at: now
  });
};

export async function up(knex: Knex): Promise<void> {
  await updatePurposeLimits(knex, "cuncta.social.account_active", [
    "social.profile.create",
    "social.post.create",
    "social.follow.create",
    "social.report.create"
  ]);
  await updatePurposeLimits(knex, "cuncta.social.can_post", ["social.post.create"]);
  await updatePurposeLimits(knex, "cuncta.social.can_comment", ["social.reply.create"]);
  await updatePurposeLimits(knex, "cuncta.social.trusted_creator", [
    "social.post.create",
    "social.reply.create"
  ]);

  await upsertAuraRule(knex, {
    rule_id: "social.can_post.v2",
    domain: "social",
    output_vct: "cuncta.social.can_post",
    version: 3,
    rule_logic: {
      purpose: "Capability to create social posts (anti-spam entitlement)",
      window_days: 7,
      signals: ["social.post_success", "social.reply_success"],
      score: { min_silver: 3, min_gold: 10 },
      diversity: { min_for_silver: 1, min_for_gold: 2 },
      diversity_min: 1,
      per_counterparty_cap: 3,
      per_counterparty_decay_exponent: 0.6,
      collusion_cluster_threshold: 0.85,
      collusion_multiplier: 0.85,
      min_tier: "silver",
      output: {
        claims: {
          can_post: true,
          tier: "{tier}",
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.trusted_creator.v1",
    domain: "social",
    output_vct: "cuncta.social.trusted_creator",
    version: 2,
    rule_logic: {
      purpose: "Capability stamp for trusted creators (feed/trust lens entitlement)",
      window_days: 30,
      signals: ["social.post_success", "social.reply_success"],
      score: { min_silver: 15, min_gold: 30 },
      diversity: { min_for_silver: 2, min_for_gold: 4 },
      diversity_min: 2,
      per_counterparty_cap: 4,
      per_counterparty_decay_exponent: 0.7,
      collusion_cluster_threshold: 0.75,
      collusion_multiplier: 0.7,
      min_tier: "silver",
      output: {
        claims: {
          trusted_creator: true,
          tier: "{tier}",
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });
}

export async function down(knex: Knex): Promise<void> {
  await updatePurposeLimits(knex, "cuncta.social.account_active", [
    "social.create_profile",
    "social.post"
  ]);
  await updatePurposeLimits(knex, "cuncta.social.can_post", ["social.post"]);
  await updatePurposeLimits(knex, "cuncta.social.can_comment", ["social.comment"]);
  await updatePurposeLimits(knex, "cuncta.social.trusted_creator", [
    "social.reply.create",
    "social.post.create"
  ]);

  await upsertAuraRule(knex, {
    rule_id: "social.can_post.v2",
    domain: "social",
    output_vct: "cuncta.social.can_post",
    version: 2,
    rule_logic: {
      purpose: "Capability to create social posts (anti-spam entitlement)",
      window_days: 30,
      signals: ["social.post_success", "social.reply_success"],
      score: { min_silver: 1, min_gold: 6 },
      diversity: { min_for_silver: 1, min_for_gold: 2 },
      anti_collusion: { top2_ratio: 0.9, multiplier: 0.9 },
      min_tier: "bronze",
      output: {
        claims: {
          can_post: true,
          tier: "{tier}",
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.trusted_creator.v1",
    domain: "social",
    output_vct: "cuncta.social.trusted_creator",
    version: 1,
    rule_logic: {
      purpose: "Capability stamp for trusted creators (feed/trust lens entitlement)",
      window_days: 30,
      signals: ["social.post_success", "social.reply_success"],
      score: { min_silver: 10, min_gold: 20 },
      diversity: { min_for_silver: 2, min_for_gold: 3 },
      anti_collusion: { top2_ratio: 0.8, multiplier: 0.8 },
      min_tier: "silver",
      output: {
        claims: {
          trusted_creator: true,
          tier: "{tier}",
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });
}
