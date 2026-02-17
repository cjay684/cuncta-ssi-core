import { Knex } from "knex";

const toJson = (value: unknown) => JSON.stringify(value);

const ensureAction = async (knex: Knex, actionId: string, description: string) => {
  const existing = await knex("actions").where({ action_id: actionId }).first();
  if (existing) return;
  const now = new Date().toISOString();
  await knex("actions").insert({
    action_id: actionId,
    description,
    created_at: now,
    updated_at: now
  });
};

const upsertPolicy = async (
  knex: Knex,
  input: { policy_id: string; action_id: string; version: number; logic: unknown }
) => {
  const existing = await knex("policies").where({ policy_id: input.policy_id }).first();
  const now = new Date().toISOString();
  const update = {
    action_id: input.action_id,
    version: input.version,
    enabled: true,
    logic: toJson(input.logic),
    updated_at: now
  };
  if (existing) {
    await knex("policies").where({ policy_id: input.policy_id }).update(update);
    return;
  }
  await knex("policies").insert({
    policy_id: input.policy_id,
    ...update,
    created_at: now
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
  const existing = await knex("aura_rules").where({ rule_id: input.rule_id }).first();
  const now = new Date().toISOString();
  const update = {
    domain: input.domain,
    output_vct: input.output_vct,
    version: input.version,
    enabled: true,
    rule_logic: toJson(input.rule_logic),
    updated_at: now
  };
  if (existing) {
    await knex("aura_rules").where({ rule_id: input.rule_id }).update(update);
    return;
  }
  await knex("aura_rules").insert({
    rule_id: input.rule_id,
    ...update,
    created_at: now
  });
};

const ensureCredentialType = async (
  knex: Knex,
  input: {
    vct: string;
    json_schema: unknown;
    sd_defaults: unknown;
    display: unknown;
    purpose_limits: unknown;
    presentation_templates: unknown;
    revocation_config: unknown;
  }
) => {
  const now = new Date().toISOString();
  const existing = await knex("credential_types").where({ vct: input.vct }).first();
  if (existing) {
    await knex("credential_types")
      .where({ vct: input.vct })
      .update({
        display: toJson(input.display),
        purpose_limits: toJson(input.purpose_limits),
        presentation_templates: toJson(input.presentation_templates),
        updated_at: now
      });
    return;
  }
  await knex("credential_types").insert({
    vct: input.vct,
    json_schema: toJson(input.json_schema),
    sd_defaults: toJson(input.sd_defaults),
    display: toJson(input.display),
    purpose_limits: toJson(input.purpose_limits),
    presentation_templates: toJson(input.presentation_templates),
    revocation_config: toJson(input.revocation_config),
    created_at: now,
    updated_at: now
  });
};

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable("social_profiles", (table) => {
    table.text("handle");
    table.text("display_name");
    table.text("bio");
    table.timestamp("deleted_at", { useTz: true });
  });

  await knex.schema.alterTable("social_posts", (table) => {
    table.text("content_text");
  });

  const hasReplies = await knex.schema.hasTable("social_replies");
  if (!hasReplies) {
    await knex.schema.createTable("social_replies", (table) => {
      table.uuid("reply_id").primary();
      table
        .uuid("post_id")
        .notNullable()
        .references("post_id")
        .inTable("social_posts")
        .onDelete("CASCADE");
      table.text("author_subject_did_hash").notNullable();
      table.text("content_text").notNullable();
      table.text("content_hash").notNullable();
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp("deleted_at", { useTz: true });
      table.index(["post_id", "created_at"], "social_replies_post_created_idx");
    });
  }

  const hasFollows = await knex.schema.hasTable("social_follows");
  if (!hasFollows) {
    await knex.schema.createTable("social_follows", (table) => {
      table.text("follower_subject_did_hash").notNullable();
      table.text("followee_subject_did_hash").notNullable();
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.primary(["follower_subject_did_hash", "followee_subject_did_hash"], {
        constraintName: "social_follows_pk"
      });
    });
  }

  const hasReports = await knex.schema.hasTable("social_reports");
  if (!hasReports) {
    await knex.schema.createTable("social_reports", (table) => {
      table.uuid("report_id").primary();
      table.text("reporter_subject_did_hash").notNullable();
      table
        .uuid("target_post_id")
        .references("post_id")
        .inTable("social_posts")
        .onDelete("SET NULL");
      table
        .uuid("target_reply_id")
        .references("reply_id")
        .inTable("social_replies")
        .onDelete("SET NULL");
      table.text("reason_code").notNullable();
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    });
  }

  const hasActionLog = await knex.schema.hasTable("social_action_log");
  if (!hasActionLog) {
    await knex.schema.createTable("social_action_log", (table) => {
      table.bigIncrements("id").primary();
      table.text("subject_did_hash").notNullable();
      table.text("action_type").notNullable();
      table.text("decision").notNullable();
      table.text("policy_id");
      table.integer("policy_version");
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.index(
        ["subject_did_hash", "action_type", "created_at"],
        "social_action_log_subject_idx"
      );
    });
  }

  await ensureCredentialType(knex, {
    vct: "cuncta.social.trusted_creator",
    json_schema: {
      type: "object",
      properties: {
        trusted_creator: { type: "boolean" },
        tier: { type: "string" },
        domain: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["trusted_creator", "tier", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["trusted_creator", "tier"],
    display: {
      title: "Trusted creator",
      claims: [
        { path: "trusted_creator", label: "Trusted creator" },
        { path: "tier", label: "Tier" }
      ]
    },
    purpose_limits: { actions: ["social.reply.create", "social.post.create"] },
    presentation_templates: { required_disclosures: ["trusted_creator", "tier"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureAction(knex, "social.profile.create", "Create social profile");
  await ensureAction(knex, "social.post.create", "Create social post");
  await ensureAction(knex, "social.reply.create", "Create social reply");
  await ensureAction(knex, "social.follow.create", "Follow social profile");
  await ensureAction(knex, "social.report.create", "Report social content");

  await upsertPolicy(knex, {
    policy_id: "social.profile.create.v1",
    action_id: "social.profile.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.account_active",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["account_active"],
          predicates: [
            { path: "account_active", op: "eq", value: true },
            { path: "domain", op: "eq", value: "social" }
          ],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.post.create.v1",
    action_id: "social.post.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.account_active",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["account_active"],
          predicates: [
            { path: "account_active", op: "eq", value: true },
            { path: "domain", op: "eq", value: "social" }
          ],
          revocation: { required: true }
        }
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.post_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.reply.create.v1",
    action_id: "social.reply.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.can_comment",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["can_comment"],
          predicates: [{ path: "can_comment", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.reply_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.follow.create.v1",
    action_id: "social.follow.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.account_active",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["account_active"],
          predicates: [{ path: "account_active", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.report.create.v1",
    action_id: "social.report.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.account_active",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["account_active"],
          predicates: [{ path: "account_active", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.can_post.v2",
    domain: "social",
    output_vct: "cuncta.social.can_post",
    version: 2,
    rule_logic: {
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

export async function down(knex: Knex): Promise<void> {
  await knex("aura_rules")
    .whereIn("rule_id", ["social.can_post.v2", "social.trusted_creator.v1"])
    .del();
  await knex("policies")
    .whereIn("policy_id", [
      "social.profile.create.v1",
      "social.post.create.v1",
      "social.reply.create.v1",
      "social.follow.create.v1",
      "social.report.create.v1"
    ])
    .del();
  await knex("actions")
    .whereIn("action_id", [
      "social.profile.create",
      "social.post.create",
      "social.reply.create",
      "social.follow.create",
      "social.report.create"
    ])
    .del();
  await knex("credential_types").where({ vct: "cuncta.social.trusted_creator" }).del();
  await knex.schema.dropTableIfExists("social_action_log");
  await knex.schema.dropTableIfExists("social_reports");
  await knex.schema.dropTableIfExists("social_follows");
  await knex.schema.dropTableIfExists("social_replies");
}
