import { Knex } from "knex";
import { createHash } from "node:crypto";

const toJson = (value: unknown) => JSON.stringify(value);
const sortValue = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map((entry) => sortValue(entry));
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.keys(record)
      .sort()
      .reduce<Record<string, unknown>>((acc, key) => {
        acc[key] = sortValue(record[key]);
        return acc;
      }, {});
  }
  return value;
};
const hashCanonicalJson = (value: unknown) =>
  createHash("sha256")
    .update(JSON.stringify(sortValue(value)))
    .digest("hex");

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
        json_schema: toJson(input.json_schema),
        sd_defaults: toJson(input.sd_defaults),
        display: toJson(input.display),
        purpose_limits: toJson(input.purpose_limits),
        presentation_templates: toJson(input.presentation_templates),
        revocation_config: toJson(input.revocation_config),
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
  const now = new Date().toISOString();
  const existing = await knex("aura_rules").where({ rule_id: input.rule_id }).first();
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

export async function up(knex: Knex): Promise<void> {
  const now = new Date().toISOString();

  const hasPolicyPacks = await knex.schema.hasTable("social_space_policy_packs");
  if (!hasPolicyPacks) {
    await knex.schema.createTable("social_space_policy_packs", (table) => {
      table.text("policy_pack_id").primary();
      table.text("display_name").notNullable();
      table.text("join_action_id").notNullable();
      table.text("post_action_id").notNullable();
      table.text("moderate_action_id").notNullable();
      table.text("visibility").notNullable().defaultTo("members");
      table.text("join_policy_hash");
      table.text("post_policy_hash");
      table.text("moderate_policy_hash");
      table.text("pinned_policy_hash_join");
      table.text("pinned_policy_hash_post");
      table.text("pinned_policy_hash_moderate");
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    });
  } else {
    const hasPinnedJoin = await knex.schema.hasColumn(
      "social_space_policy_packs",
      "pinned_policy_hash_join"
    );
    if (!hasPinnedJoin) {
      await knex.schema.alterTable("social_space_policy_packs", (table) => {
        table.text("pinned_policy_hash_join");
      });
    }
    const hasPinnedPost = await knex.schema.hasColumn(
      "social_space_policy_packs",
      "pinned_policy_hash_post"
    );
    if (!hasPinnedPost) {
      await knex.schema.alterTable("social_space_policy_packs", (table) => {
        table.text("pinned_policy_hash_post");
      });
    }
    const hasPinnedModerate = await knex.schema.hasColumn(
      "social_space_policy_packs",
      "pinned_policy_hash_moderate"
    );
    if (!hasPinnedModerate) {
      await knex.schema.alterTable("social_space_policy_packs", (table) => {
        table.text("pinned_policy_hash_moderate");
      });
    }
  }

  const hasSpaces = await knex.schema.hasTable("social_spaces");
  if (!hasSpaces) {
    await knex.schema.createTable("social_spaces", (table) => {
      table.uuid("space_id").primary();
      table.text("slug").notNullable().unique();
      table.text("display_name").notNullable();
      table.text("description");
      table.text("created_by_subject_did_hash").notNullable();
      table.text("policy_pack_id").notNullable();
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp("archived_at", { useTz: true });
      table.index(["created_by_subject_did_hash", "created_at"], "social_spaces_creator_idx");
    });
  }

  const hasMemberships = await knex.schema.hasTable("social_space_memberships");
  if (!hasMemberships) {
    await knex.schema.createTable("social_space_memberships", (table) => {
      table.uuid("space_id").notNullable();
      table.text("subject_did_hash").notNullable();
      table.text("status").notNullable().defaultTo("ACTIVE");
      table.timestamp("joined_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp("left_at", { useTz: true });
      table.primary(["space_id", "subject_did_hash"], {
        constraintName: "social_space_memberships_pk"
      });
      table.index(["subject_did_hash", "joined_at"], "social_space_memberships_subject_idx");
    });
  }

  const hasSpacePosts = await knex.schema.hasTable("social_space_posts");
  if (!hasSpacePosts) {
    await knex.schema.createTable("social_space_posts", (table) => {
      table.uuid("space_post_id").primary();
      table.uuid("space_id").notNullable();
      table.text("author_subject_did_hash").notNullable();
      table.text("content_text").notNullable();
      table.text("content_hash").notNullable();
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.timestamp("deleted_at", { useTz: true });
      table.index(["space_id", "created_at"], "social_space_posts_space_created_idx");
      table.index(
        ["author_subject_did_hash", "created_at"],
        "social_space_posts_author_created_idx"
      );
    });
  }

  const hasModeration = await knex.schema.hasTable("social_space_moderation_actions");
  if (!hasModeration) {
    await knex.schema.createTable("social_space_moderation_actions", (table) => {
      table.uuid("moderation_id").primary();
      table.uuid("space_id").notNullable();
      table.text("moderator_subject_did_hash").notNullable();
      table.text("target_subject_did_hash");
      table.uuid("target_space_post_id");
      table.text("operation").notNullable();
      table.text("reason_code").notNullable();
      table.text("audit_hash").notNullable().unique();
      table.boolean("anchor_requested").notNullable().defaultTo(false);
      table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.index(["space_id", "created_at"], "social_space_moderation_space_created_idx");
    });
  }

  const hasSpaceRestrictions = await knex.schema.hasTable("social_space_member_restrictions");
  if (!hasSpaceRestrictions) {
    await knex.schema.createTable("social_space_member_restrictions", (table) => {
      table.uuid("space_id").notNullable();
      table.text("subject_did_hash").notNullable();
      table.text("reason_code").notNullable();
      table.timestamp("restricted_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
      table.primary(["space_id", "subject_did_hash"], {
        constraintName: "social_space_member_restrictions_pk"
      });
    });
  }

  await ensureAction(knex, "social.space.create", "Create a social trust space");
  await ensureAction(knex, "social.space.join", "Join a social trust space");
  await ensureAction(knex, "social.space.post.create", "Create a post inside a space");
  await ensureAction(knex, "social.space.moderate", "Moderate content or members in a space");

  await ensureCredentialType(knex, {
    vct: "cuncta.social.space.member",
    json_schema: {
      type: "object",
      properties: {
        member: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["member", "domain", "space_id", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["member", "space_id"],
    display: {
      title: "Space Member",
      claims: [
        { path: "member", label: "Member" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: { actions: ["social.space.join"] },
    presentation_templates: { required_disclosures: ["member", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.space.poster",
    json_schema: {
      type: "object",
      properties: {
        poster: { type: "boolean" },
        tier: { type: "string" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["poster", "tier", "domain", "space_id", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["poster", "space_id", "tier"],
    display: {
      title: "Space Poster",
      claims: [
        { path: "poster", label: "Poster" },
        { path: "tier", label: "Tier" }
      ]
    },
    purpose_limits: { actions: ["social.space.post.create"] },
    presentation_templates: { required_disclosures: ["poster", "space_id", "tier"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.space.moderator",
    json_schema: {
      type: "object",
      properties: {
        moderator: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["moderator", "domain", "space_id", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["moderator", "space_id"],
    display: {
      title: "Space Moderator",
      claims: [
        { path: "moderator", label: "Moderator" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: { actions: ["social.space.moderate"] },
    presentation_templates: { required_disclosures: ["moderator", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.space.steward",
    json_schema: {
      type: "object",
      properties: {
        steward: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["steward", "domain", "space_id", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["steward", "space_id"],
    display: {
      title: "Space Steward",
      claims: [
        { path: "steward", label: "Steward" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: { actions: ["social.space.create", "social.space.moderate"] },
    presentation_templates: { required_disclosures: ["steward", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await upsertPolicy(knex, {
    policy_id: "social.space.create.v1",
    action_id: "social.space.create",
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
    policy_id: "social.space.join.v1",
    action_id: "social.space.join",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.space.member",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["member", "space_id"],
          predicates: [
            { path: "member", op: "eq", value: true },
            { path: "space_id", op: "exists" },
            { path: "domain", op: "exists" }
          ],
          context_predicates: [{ left: "context.space_id", right: "claims.space_id", op: "eq" }],
          revocation: { required: true }
        }
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.space.join_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });
  await upsertPolicy(knex, {
    policy_id: "social.space.post.create.v1",
    action_id: "social.space.post.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.space.poster",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["poster", "space_id", "tier"],
          predicates: [
            { path: "poster", op: "eq", value: true },
            { path: "space_id", op: "exists" },
            { path: "domain", op: "exists" }
          ],
          context_predicates: [{ left: "context.space_id", right: "claims.space_id", op: "eq" }],
          revocation: { required: true }
        }
      ],
      obligations: [
        { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
        { type: "AURA_SIGNAL", signal: "social.space.post_success", weight: 1, when: "ON_ALLOW" }
      ]
    }
  });
  await upsertPolicy(knex, {
    policy_id: "social.space.moderate.v1",
    action_id: "social.space.moderate",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.space.moderator",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["moderator", "space_id"],
          predicates: [
            { path: "moderator", op: "eq", value: true },
            { path: "space_id", op: "exists" },
            { path: "domain", op: "exists" }
          ],
          context_predicates: [{ left: "context.space_id", right: "claims.space_id", op: "eq" }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });

  await upsertAuraRule(knex, {
    rule_id: "social.space.member.v1",
    domain: "*",
    output_vct: "cuncta.social.space.member",
    version: 1,
    rule_logic: {
      window_days: 30,
      signals: ["social.space.join_success"],
      score: { min_silver: 1, min_gold: 2 },
      diversity: { min_for_silver: 1, min_for_gold: 1 },
      diversity_min: 1,
      min_tier: "bronze",
      output: {
        claims: {
          member: true,
          domain: "{domain}",
          space_id: "{space_id}",
          as_of: "{now}"
        }
      }
    }
  });
  await upsertAuraRule(knex, {
    rule_id: "social.space.poster.v1",
    domain: "*",
    output_vct: "cuncta.social.space.poster",
    version: 1,
    rule_logic: {
      window_days: 30,
      signals: ["social.space.post_success"],
      score: { min_silver: 1, min_gold: 5 },
      diversity: { min_for_silver: 1, min_for_gold: 2 },
      diversity_min: 1,
      min_tier: "bronze",
      output: {
        claims: {
          poster: true,
          tier: "{tier}",
          domain: "{domain}",
          space_id: "{space_id}",
          as_of: "{now}"
        }
      }
    }
  });
  await upsertAuraRule(knex, {
    rule_id: "social.space.moderator.v1",
    domain: "*",
    output_vct: "cuncta.social.space.moderator",
    version: 1,
    rule_logic: {
      window_days: 45,
      signals: ["social.space.post_success", "social.space.join_success"],
      score: { min_silver: 8, min_gold: 15 },
      diversity: { min_for_silver: 2, min_for_gold: 3 },
      diversity_min: 2,
      min_tier: "silver",
      output: {
        claims: {
          moderator: true,
          domain: "{domain}",
          space_id: "{space_id}",
          as_of: "{now}"
        }
      }
    }
  });
  await upsertAuraRule(knex, {
    rule_id: "social.space.steward.v1",
    domain: "*",
    output_vct: "cuncta.social.space.steward",
    version: 1,
    rule_logic: {
      window_days: 60,
      signals: ["social.space.post_success", "social.space.join_success"],
      score: { min_silver: 12, min_gold: 20 },
      diversity: { min_for_silver: 3, min_for_gold: 5 },
      diversity_min: 3,
      min_tier: "silver",
      output: {
        claims: {
          steward: true,
          domain: "{domain}",
          space_id: "{space_id}",
          as_of: "{now}"
        }
      }
    }
  });

  const computeActionPolicyHash = async (actionId: string) => {
    const policy = await knex("policies")
      .where({ action_id: actionId, enabled: true })
      .orderBy("version", "desc")
      .first();
    if (!policy) return null;
    const logicRaw = policy.logic as unknown;
    const logic =
      typeof logicRaw === "string"
        ? (JSON.parse(logicRaw) as Record<string, unknown>)
        : (logicRaw as Record<string, unknown>);
    return hashCanonicalJson({
      policy_id: policy.policy_id,
      action_id: policy.action_id,
      version: policy.version,
      enabled: policy.enabled,
      logic
    });
  };
  const joinPolicyHash = await computeActionPolicyHash("social.space.join");
  const postPolicyHash = await computeActionPolicyHash("social.space.post.create");
  const moderatePolicyHash = await computeActionPolicyHash("social.space.moderate");

  const existingPack = await knex("social_space_policy_packs")
    .where({ policy_pack_id: "space.default.v1" })
    .first();
  if (!existingPack) {
    await knex("social_space_policy_packs").insert({
      policy_pack_id: "space.default.v1",
      display_name: "Default Space Pack v1",
      join_action_id: "social.space.join",
      post_action_id: "social.space.post.create",
      moderate_action_id: "social.space.moderate",
      visibility: "members",
      join_policy_hash: joinPolicyHash,
      post_policy_hash: postPolicyHash,
      moderate_policy_hash: moderatePolicyHash,
      pinned_policy_hash_join: joinPolicyHash,
      pinned_policy_hash_post: postPolicyHash,
      pinned_policy_hash_moderate: moderatePolicyHash,
      created_at: now,
      updated_at: now
    });
  } else {
    await knex("social_space_policy_packs").where({ policy_pack_id: "space.default.v1" }).update({
      join_policy_hash: joinPolicyHash,
      post_policy_hash: postPolicyHash,
      moderate_policy_hash: moderatePolicyHash,
      pinned_policy_hash_join: joinPolicyHash,
      pinned_policy_hash_post: postPolicyHash,
      pinned_policy_hash_moderate: moderatePolicyHash,
      updated_at: now
    });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex("social_space_policy_packs").where({ policy_pack_id: "space.default.v1" }).del();
  await knex("aura_rules")
    .whereIn("rule_id", [
      "social.space.member.v1",
      "social.space.poster.v1",
      "social.space.moderator.v1",
      "social.space.steward.v1"
    ])
    .del();
  await knex("policies")
    .whereIn("policy_id", [
      "social.space.create.v1",
      "social.space.join.v1",
      "social.space.post.create.v1",
      "social.space.moderate.v1"
    ])
    .del();
  await knex("actions")
    .whereIn("action_id", [
      "social.space.create",
      "social.space.join",
      "social.space.post.create",
      "social.space.moderate"
    ])
    .del();
  await knex("credential_types")
    .whereIn("vct", [
      "cuncta.social.space.member",
      "cuncta.social.space.poster",
      "cuncta.social.space.moderator",
      "cuncta.social.space.steward"
    ])
    .del();

  await knex.schema.dropTableIfExists("social_space_member_restrictions");
  await knex.schema.dropTableIfExists("social_space_moderation_actions");
  await knex.schema.dropTableIfExists("social_space_posts");
  await knex.schema.dropTableIfExists("social_space_memberships");
  await knex.schema.dropTableIfExists("social_spaces");
  await knex.schema.dropTableIfExists("social_space_policy_packs");
}
