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
  const now = new Date().toISOString();
  const existing = await knex("policies").where({ policy_id: input.policy_id }).first();
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

const withSpaceBinding = (
  vct: string,
  disclosures: string[],
  extraPredicates: Array<Record<string, unknown>> = []
) => ({
  binding: { mode: "kb-jwt", require: true },
  requirements: [
    {
      vct,
      issuer: { mode: "env", env: "ISSUER_DID" },
      disclosures,
      predicates: [...extraPredicates, { path: "space_id", op: "exists" }],
      context_predicates: [{ left: "context.space_id", right: "claims.space_id", op: "eq" }],
      revocation: { required: true }
    }
  ],
  obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
});

export async function up(knex: Knex): Promise<void> {
  const now = new Date().toISOString();
  await knex.schema.createTable("media_emoji_assets", (table) => {
    table.uuid("id").primary();
    table.text("creator_subject_hash").notNullable();
    table.uuid("space_id");
    table.text("asset_ref").notNullable();
    table.text("hash").notNullable();
    table.text("status").notNullable().defaultTo("ACTIVE");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("deleted_at", { useTz: true });
    table.index(["creator_subject_hash", "created_at"], "media_emoji_assets_creator_idx");
    table.index(["space_id", "created_at"], "media_emoji_assets_space_idx");
  });
  await knex.schema.createTable("media_emoji_packs", (table) => {
    table.uuid("id").primary();
    table.text("owner_subject_hash").notNullable();
    table.uuid("space_id");
    table.text("visibility").notNullable().defaultTo("private");
    table.integer("version").notNullable().defaultTo(1);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("published_at", { useTz: true });
    table.index(["owner_subject_hash", "created_at"], "media_emoji_packs_owner_idx");
    table.index(["space_id", "published_at"], "media_emoji_packs_space_idx");
  });
  await knex.schema.createTable("media_emoji_pack_assets", (table) => {
    table.uuid("pack_id").notNullable();
    table.uuid("asset_id").notNullable();
    table.primary(["pack_id", "asset_id"], { constraintName: "media_emoji_pack_assets_pk" });
  });
  await knex.schema.createTable("media_sound_assets", (table) => {
    table.uuid("id").primary();
    table.text("creator_subject_hash").notNullable();
    table.uuid("space_id");
    table.text("asset_ref").notNullable();
    table.text("hash").notNullable();
    table.integer("duration_ms").notNullable().defaultTo(0);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["creator_subject_hash", "created_at"], "media_sound_assets_creator_idx");
  });
  await knex.schema.createTable("media_soundpacks", (table) => {
    table.uuid("id").primary();
    table.text("owner_subject_hash").notNullable();
    table.uuid("space_id");
    table.text("visibility").notNullable().defaultTo("private");
    table.integer("version").notNullable().defaultTo(1);
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("published_at", { useTz: true });
    table.index(["owner_subject_hash", "created_at"], "media_soundpacks_owner_idx");
  });
  await knex.schema.createTable("media_soundpack_assets", (table) => {
    table.uuid("pack_id").notNullable();
    table.uuid("asset_id").notNullable();
    table.primary(["pack_id", "asset_id"], { constraintName: "media_soundpack_assets_pk" });
  });
  await knex.schema.createTable("media_soundpack_activations", (table) => {
    table.uuid("space_id").notNullable();
    table.uuid("pack_id").notNullable();
    table.text("activated_by_subject_hash").notNullable();
    table.timestamp("activated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("deactivated_at", { useTz: true });
    table.primary(["space_id", "pack_id", "activated_at"], {
      constraintName: "media_soundpack_activations_pk"
    });
    table.index(["space_id", "deactivated_at"], "media_soundpack_activations_space_idx");
  });
  await knex.schema.createTable("presence_space_states", (table) => {
    table.uuid("space_id").notNullable();
    table.text("subject_hash").notNullable();
    table.text("mode").notNullable().defaultTo("active");
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["space_id", "subject_hash"], { constraintName: "presence_space_states_pk" });
  });
  await knex.schema.createTable("presence_invite_events", (table) => {
    table.uuid("id").primary();
    table.uuid("space_id").notNullable();
    table.text("inviter_hash").notNullable();
    table.text("invitee_hash").notNullable();
    table.text("session_ref").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("status").notNullable().defaultTo("SENT");
    table.index(["space_id", "created_at"], "presence_invite_events_space_idx");
  });
  await knex.schema.createTable("sync_watch_sessions", (table) => {
    table.uuid("id").primary();
    table.uuid("space_id").notNullable();
    table.text("host_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("ended_at", { useTz: true });
    table.text("status").notNullable().defaultTo("ACTIVE");
    table.index(["space_id", "status", "created_at"], "sync_watch_sessions_space_idx");
  });
  await knex.schema.createTable("sync_watch_participants", (table) => {
    table.uuid("session_id").notNullable();
    table.text("subject_hash").notNullable();
    table.timestamp("joined_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("left_at", { useTz: true });
    table.primary(["session_id", "subject_hash"], { constraintName: "sync_watch_participants_pk" });
  });

  const actions: Array<[string, string]> = [
    ["media.emoji.create", "Create emoji asset"],
    ["media.emoji.pack.create", "Create emoji pack"],
    ["media.emoji.pack.publish", "Publish emoji pack to space"],
    ["media.asset.report", "Report media asset abuse"],
    ["media.asset.moderate", "Moderate media asset"],
    ["media.soundpack.create", "Create soundpack asset"],
    ["media.soundpack.publish", "Publish soundpack"],
    ["media.soundpack.activate_in_space", "Activate soundpack in space"],
    ["presence.set_mode", "Set presence mode"],
    ["presence.join_space_presence", "Join space presence"],
    ["presence.leave_space_presence", "Leave space presence"],
    ["presence.invite_to_session", "Invite to session"],
    ["presence.report_status_abuse", "Report presence abuse"],
    ["sync.watch.create_session", "Create watch session"],
    ["sync.watch.join_session", "Join watch session"],
    ["sync.watch.end_session", "End watch session"],
    ["sync.session.report", "Report watch session abuse"],
    ["sync.session.moderate", "Moderate watch session"]
  ];
  for (const [actionId, description] of actions) {
    await ensureAction(knex, actionId, description);
  }

  await ensureCredentialType(knex, {
    vct: "cuncta.media.emoji_creator",
    json_schema: {
      type: "object",
      properties: {
        emoji_creator: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["emoji_creator", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["emoji_creator", "space_id"],
    display: {
      title: "Emoji Creator",
      claims: [
        { path: "emoji_creator", label: "Emoji creator" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: [
        "media.emoji.create",
        "media.emoji.pack.create",
        "media.emoji.pack.publish",
        "media.asset.report"
      ]
    },
    presentation_templates: { required_disclosures: ["emoji_creator", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });
  await ensureCredentialType(knex, {
    vct: "cuncta.media.soundpack_creator",
    json_schema: {
      type: "object",
      properties: {
        soundpack_creator: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["soundpack_creator", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["soundpack_creator", "space_id"],
    display: {
      title: "Soundpack Creator",
      claims: [
        { path: "soundpack_creator", label: "Soundpack creator" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: [
        "media.soundpack.create",
        "media.soundpack.publish",
        "media.soundpack.activate_in_space"
      ]
    },
    presentation_templates: { required_disclosures: ["soundpack_creator", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });
  await ensureCredentialType(knex, {
    vct: "cuncta.sync.watch_host",
    json_schema: {
      type: "object",
      properties: {
        watch_host: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["watch_host", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["watch_host", "space_id"],
    display: {
      title: "Watch Host",
      claims: [
        { path: "watch_host", label: "Watch host" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: [
        "sync.watch.create_session",
        "sync.watch.join_session",
        "sync.watch.end_session",
        "sync.session.report"
      ]
    },
    presentation_templates: { required_disclosures: ["watch_host", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });
  await ensureCredentialType(knex, {
    vct: "cuncta.presence.mode_access",
    json_schema: {
      type: "object",
      properties: {
        mode_access: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["mode_access", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["mode_access", "space_id"],
    display: {
      title: "Presence Access",
      claims: [
        { path: "mode_access", label: "Presence mode access" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: [
        "presence.set_mode",
        "presence.join_space_presence",
        "presence.leave_space_presence",
        "presence.invite_to_session",
        "presence.report_status_abuse",
        "sync.watch.join_session"
      ]
    },
    presentation_templates: { required_disclosures: ["mode_access", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await upsertPolicy(knex, {
    policy_id: "media.emoji.create.v1",
    action_id: "media.emoji.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.media.emoji_creator",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["emoji_creator"],
          predicates: [{ path: "emoji_creator", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });
  await upsertPolicy(knex, {
    policy_id: "media.emoji.pack.create.v1",
    action_id: "media.emoji.pack.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.media.emoji_creator",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["emoji_creator"],
          predicates: [{ path: "emoji_creator", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });
  await upsertPolicy(knex, {
    policy_id: "media.emoji.pack.publish.v1",
    action_id: "media.emoji.pack.publish",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.media.emoji_creator",
      ["emoji_creator", "space_id"],
      [{ path: "emoji_creator", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "media.asset.report.v1",
    action_id: "media.asset.report",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "media.asset.moderate.v1",
    action_id: "media.asset.moderate",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.moderator",
      ["moderator", "space_id"],
      [{ path: "moderator", op: "eq", value: true }]
    )
  });

  await upsertPolicy(knex, {
    policy_id: "media.soundpack.create.v1",
    action_id: "media.soundpack.create",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.media.soundpack_creator",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["soundpack_creator"],
          predicates: [{ path: "soundpack_creator", op: "eq", value: true }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });
  await upsertPolicy(knex, {
    policy_id: "media.soundpack.publish.v1",
    action_id: "media.soundpack.publish",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.media.soundpack_creator",
      ["soundpack_creator", "space_id"],
      [{ path: "soundpack_creator", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "media.soundpack.activate_in_space.v1",
    action_id: "media.soundpack.activate_in_space",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.media.soundpack_creator",
      ["soundpack_creator", "space_id"],
      [{ path: "soundpack_creator", op: "eq", value: true }]
    )
  });

  await upsertPolicy(knex, {
    policy_id: "presence.set_mode.v1",
    action_id: "presence.set_mode",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "presence.join_space_presence.v1",
    action_id: "presence.join_space_presence",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "presence.leave_space_presence.v1",
    action_id: "presence.leave_space_presence",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "presence.invite_to_session.v1",
    action_id: "presence.invite_to_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "presence.report_status_abuse.v1",
    action_id: "presence.report_status_abuse",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });

  await upsertPolicy(knex, {
    policy_id: "sync.watch.create_session.v1",
    action_id: "sync.watch.create_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.watch_host",
      ["watch_host", "space_id"],
      [{ path: "watch_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.watch.join_session.v1",
    action_id: "sync.watch.join_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.watch.end_session.v1",
    action_id: "sync.watch.end_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.watch_host",
      ["watch_host", "space_id"],
      [{ path: "watch_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.session.report.v1",
    action_id: "sync.session.report",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.session.moderate.v1",
    action_id: "sync.session.moderate",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.moderator",
      ["moderator", "space_id"],
      [{ path: "moderator", op: "eq", value: true }]
    )
  });

  await knex("credential_types")
    .whereIn("vct", [
      "cuncta.media.emoji_creator",
      "cuncta.media.soundpack_creator",
      "cuncta.sync.watch_host",
      "cuncta.presence.mode_access"
    ])
    .update({ updated_at: now });
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies")
    .whereIn("action_id", [
      "media.emoji.create",
      "media.emoji.pack.create",
      "media.emoji.pack.publish",
      "media.asset.report",
      "media.asset.moderate",
      "media.soundpack.create",
      "media.soundpack.publish",
      "media.soundpack.activate_in_space",
      "presence.set_mode",
      "presence.join_space_presence",
      "presence.leave_space_presence",
      "presence.invite_to_session",
      "presence.report_status_abuse",
      "sync.watch.create_session",
      "sync.watch.join_session",
      "sync.watch.end_session",
      "sync.session.report",
      "sync.session.moderate"
    ])
    .del();
  await knex("actions")
    .whereIn("action_id", [
      "media.emoji.create",
      "media.emoji.pack.create",
      "media.emoji.pack.publish",
      "media.asset.report",
      "media.asset.moderate",
      "media.soundpack.create",
      "media.soundpack.publish",
      "media.soundpack.activate_in_space",
      "presence.set_mode",
      "presence.join_space_presence",
      "presence.leave_space_presence",
      "presence.invite_to_session",
      "presence.report_status_abuse",
      "sync.watch.create_session",
      "sync.watch.join_session",
      "sync.watch.end_session",
      "sync.session.report",
      "sync.session.moderate"
    ])
    .del();
  await knex("credential_types")
    .whereIn("vct", [
      "cuncta.media.emoji_creator",
      "cuncta.media.soundpack_creator",
      "cuncta.sync.watch_host",
      "cuncta.presence.mode_access"
    ])
    .del();

  await knex.schema.dropTableIfExists("sync_watch_participants");
  await knex.schema.dropTableIfExists("sync_watch_sessions");
  await knex.schema.dropTableIfExists("presence_invite_events");
  await knex.schema.dropTableIfExists("presence_space_states");
  await knex.schema.dropTableIfExists("media_soundpack_activations");
  await knex.schema.dropTableIfExists("media_soundpack_assets");
  await knex.schema.dropTableIfExists("media_soundpacks");
  await knex.schema.dropTableIfExists("media_sound_assets");
  await knex.schema.dropTableIfExists("media_emoji_pack_assets");
  await knex.schema.dropTableIfExists("media_emoji_packs");
  await knex.schema.dropTableIfExists("media_emoji_assets");
}
