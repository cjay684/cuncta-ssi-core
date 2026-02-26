import { Knex } from "knex";

const toJson = (value: unknown) => JSON.stringify(value);

const ensureAction = async (knex: Knex, actionId: string, description: string) => {
  const existing = await knex("actions").where({ action_id: actionId }).first();
  if (existing) return;
  await knex("actions").insert({
    action_id: actionId,
    description,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
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
  const existing = await knex("credential_types").where({ vct: input.vct }).first();
  if (existing) return;
  await knex("credential_types").insert({
    vct: input.vct,
    json_schema: toJson(input.json_schema),
    sd_defaults: toJson(input.sd_defaults),
    display: toJson(input.display),
    purpose_limits: toJson(input.purpose_limits),
    presentation_templates: toJson(input.presentation_templates),
    revocation_config: toJson(input.revocation_config),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });
};

const upsertPolicy = async (
  knex: Knex,
  input: {
    policy_id: string;
    action_id: string;
    version: number;
    logic: unknown;
  }
) => {
  const existing = await knex("policies").where({ policy_id: input.policy_id }).first();
  const next = {
    action_id: input.action_id,
    version: input.version,
    enabled: true,
    logic: toJson(input.logic),
    updated_at: new Date().toISOString()
  };
  if (existing) {
    await knex("policies").where({ policy_id: input.policy_id }).update(next);
    return;
  }
  await knex("policies").insert({
    policy_id: input.policy_id,
    ...next,
    created_at: new Date().toISOString()
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
  const next = {
    domain: input.domain,
    output_vct: input.output_vct,
    version: input.version,
    enabled: true,
    rule_logic: toJson(input.rule_logic),
    updated_at: new Date().toISOString()
  };
  if (existing) {
    await knex("aura_rules").where({ rule_id: input.rule_id }).update(next);
    return;
  }
  await knex("aura_rules").insert({
    rule_id: input.rule_id,
    ...next,
    created_at: new Date().toISOString()
  });
};

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("social_profiles", (table) => {
    table.uuid("profile_id").primary();
    table.text("subject_did_hash").notNullable().unique();
    table.text("handle_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["subject_did_hash"], "social_profiles_subject_idx");
  });

  await knex.schema.createTable("social_posts", (table) => {
    table.uuid("post_id").primary();
    table.text("author_subject_did_hash").notNullable();
    table.text("content_hash").notNullable();
    table.text("content_ciphertext");
    table.text("visibility").notNullable().defaultTo("public");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("deleted_at", { useTz: true });
    table.index(["author_subject_did_hash", "created_at"], "social_posts_author_created_idx");
    table.index(["visibility", "created_at"], "social_posts_visibility_created_idx");
  });

  // Product data table intentionally separated from SSI-core records.
  await knex.schema.createTable("social_post_content", (table) => {
    table
      .uuid("post_id")
      .primary()
      .references("post_id")
      .inTable("social_posts")
      .onDelete("CASCADE");
    table.text("content_text").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("social_actions_log", (table) => {
    table.bigIncrements("id").primary();
    table.text("subject_did_hash").notNullable();
    table.text("action_type").notNullable();
    table.text("entity_id_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["subject_did_hash", "action_type", "created_at"], "social_actions_subject_idx");
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.account_active",
    json_schema: {
      type: "object",
      properties: {
        account_active: { type: "boolean" },
        domain: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["account_active", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["account_active"],
    display: {
      title: "Social Account Active",
      claims: [{ path: "account_active", label: "Account active" }]
    },
    purpose_limits: { actions: ["social.create_profile", "social.post"] },
    presentation_templates: { required_disclosures: ["account_active"] },
    revocation_config: {
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.can_post",
    json_schema: {
      type: "object",
      properties: {
        can_post: { type: "boolean" },
        tier: { type: "string", enum: ["bronze", "silver", "gold"] },
        domain: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["can_post", "tier", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["can_post", "tier"],
    display: {
      title: "Social Post Capability",
      claims: [
        { path: "can_post", label: "Can post" },
        { path: "tier", label: "Tier" }
      ]
    },
    purpose_limits: { actions: ["social.post"] },
    presentation_templates: { required_disclosures: ["can_post", "tier"] },
    revocation_config: {
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.can_comment",
    json_schema: {
      type: "object",
      properties: {
        can_comment: { type: "boolean" },
        tier: { type: "string", enum: ["bronze", "silver", "gold"] },
        domain: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["can_comment", "tier", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["can_comment"],
    display: {
      title: "Social Comment Capability",
      claims: [{ path: "can_comment", label: "Can comment" }]
    },
    purpose_limits: { actions: ["social.comment"] },
    presentation_templates: { required_disclosures: ["can_comment"] },
    revocation_config: {
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.can_follow",
    json_schema: {
      type: "object",
      properties: {
        can_follow: { type: "boolean" },
        domain: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["can_follow", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["can_follow"],
    display: {
      title: "Social Follow Capability",
      claims: [{ path: "can_follow", label: "Can follow" }]
    },
    purpose_limits: { actions: ["social.follow"] },
    presentation_templates: { required_disclosures: ["can_follow"] },
    revocation_config: {
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.community_member",
    json_schema: {
      type: "object",
      properties: {
        community_member: { type: "boolean" },
        community_id: { type: "string" },
        domain: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["community_member", "community_id", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["community_member", "community_id"],
    display: {
      title: "Community Member",
      claims: [{ path: "community_id", label: "Community" }]
    },
    purpose_limits: { actions: ["social.join_community"] },
    presentation_templates: { required_disclosures: ["community_member", "community_id"] },
    revocation_config: {
      statusPurpose: "revocation",
      statusListId: "default",
      bitstringSize: 2048
    }
  });

  await ensureAction(knex, "social.create_profile", "Create a social profile");
  await ensureAction(knex, "social.post", "Create a social post");
  await ensureAction(knex, "social.comment", "Create a social comment");
  await ensureAction(knex, "social.follow", "Follow a social profile");
  await ensureAction(knex, "social.join_community", "Join a social community");

  await upsertPolicy(knex, {
    policy_id: "social.create_profile.v1",
    action_id: "social.create_profile",
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
    policy_id: "social.post.v1",
    action_id: "social.post",
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
        { type: "EMIT_EVENT", event: "SOCIAL_POST_SUCCESS", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.post_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.comment.v1",
    action_id: "social.comment",
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
        { type: "EMIT_EVENT", event: "SOCIAL_COMMENT_SUCCESS", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.comment_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.follow.v1",
    action_id: "social.follow",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.can_follow",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["can_follow"],
          predicates: [{ path: "can_follow", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.follow_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });

  await upsertPolicy(knex, {
    policy_id: "social.join_community.v1",
    action_id: "social.join_community",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.community_member",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["community_member", "community_id"],
          predicates: [{ path: "community_member", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
        {
          type: "AURA_SIGNAL",
          signal: "social.community_join_success",
          weight: 1,
          when: "ON_ALLOW"
        }
      ]
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.can_post.v1",
    domain: "social",
    output_vct: "cuncta.social.can_post",
    version: 1,
    rule_logic: {
      purpose: "Capability to create social posts (anti-spam entitlement)",
      window_days: 30,
      signals: ["social.post_success"],
      score: { min_silver: 3, min_gold: 10 },
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
    rule_id: "social.can_comment.v1",
    domain: "social",
    output_vct: "cuncta.social.can_comment",
    version: 1,
    rule_logic: {
      purpose: "Capability to create social replies/comments (anti-spam entitlement)",
      window_days: 30,
      signals: ["social.post_success"],
      score: { min_silver: 2, min_gold: 8 },
      diversity: { min_for_silver: 1, min_for_gold: 2 },
      anti_collusion: { top2_ratio: 0.9, multiplier: 0.9 },
      min_tier: "bronze",
      output: {
        claims: {
          can_comment: true,
          tier: "{tier}",
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.can_follow.v1",
    domain: "social",
    output_vct: "cuncta.social.can_follow",
    version: 1,
    rule_logic: {
      purpose: "Capability to follow social profiles (anti-abuse entitlement)",
      window_days: 30,
      signals: ["social.comment_success", "social.post_success"],
      score: { min_silver: 3, min_gold: 12 },
      diversity: { min_for_silver: 1, min_for_gold: 2 },
      anti_collusion: { top2_ratio: 0.9, multiplier: 0.9 },
      min_tier: "bronze",
      output: {
        claims: {
          can_follow: true,
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.community_member.v1",
    domain: "social",
    output_vct: "cuncta.social.community_member",
    version: 1,
    rule_logic: {
      purpose: "Capability to join the default social community (membership entitlement)",
      window_days: 30,
      signals: ["social.post_success", "social.comment_success"],
      score: { min_silver: 4, min_gold: 12 },
      diversity: { min_for_silver: 1, min_for_gold: 2 },
      anti_collusion: { top2_ratio: 0.9, multiplier: 0.9 },
      min_tier: "silver",
      output: {
        claims: {
          community_member: true,
          community_id: "cuncta.social.default",
          domain: "{domain}",
          as_of: "{now}"
        }
      }
    }
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex("aura_rules")
    .whereIn("rule_id", [
      "social.can_post.v1",
      "social.can_comment.v1",
      "social.can_follow.v1",
      "social.community_member.v1"
    ])
    .del();

  await knex("policies")
    .whereIn("policy_id", [
      "social.create_profile.v1",
      "social.post.v1",
      "social.comment.v1",
      "social.follow.v1",
      "social.join_community.v1"
    ])
    .del();

  await knex("actions")
    .whereIn("action_id", [
      "social.create_profile",
      "social.post",
      "social.comment",
      "social.follow",
      "social.join_community"
    ])
    .del();

  await knex("credential_types")
    .whereIn("vct", [
      "cuncta.social.account_active",
      "cuncta.social.can_post",
      "cuncta.social.can_comment",
      "cuncta.social.can_follow",
      "cuncta.social.community_member"
    ])
    .del();

  await knex.schema.dropTableIfExists("social_actions_log");
  await knex.schema.dropTableIfExists("social_post_content");
  await knex.schema.dropTableIfExists("social_posts");
  await knex.schema.dropTableIfExists("social_profiles");
}
