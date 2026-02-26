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

const updatePurposeLimits = async (knex: Knex, vct: string, appendActions: string[]) => {
  const existing = await knex("credential_types").where({ vct }).first();
  if (!existing) return;
  let currentActions: string[] = [];
  const parsed = existing.purpose_limits;
  if (
    parsed &&
    typeof parsed === "object" &&
    Array.isArray((parsed as { actions?: string[] }).actions)
  ) {
    currentActions = [...((parsed as { actions: string[] }).actions ?? [])];
  } else if (typeof parsed === "string") {
    try {
      const parsedJson = JSON.parse(parsed) as { actions?: string[] };
      if (Array.isArray(parsedJson.actions)) currentActions = [...parsedJson.actions];
    } catch {
      currentActions = [];
    }
  }
  const merged = Array.from(new Set([...currentActions, ...appendActions]));
  await knex("credential_types")
    .where({ vct })
    .update({
      purpose_limits: toJson({ actions: merged }),
      updated_at: new Date().toISOString()
    });
};

export async function up(knex: Knex): Promise<void> {
  const now = new Date().toISOString();
  await knex.schema.createTable("social_space_presence_pings", (table) => {
    table.uuid("space_id").notNullable();
    table.text("subject_hash").notNullable();
    table.timestamp("last_seen_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["space_id", "subject_hash"], {
      constraintName: "social_space_presence_pings_pk"
    });
    table.index(["space_id", "last_seen_at"], "social_space_presence_pings_space_last_seen_idx");
  });

  await knex.schema.createTable("social_space_profile_settings", (table) => {
    table.uuid("space_id").notNullable();
    table.text("subject_hash").notNullable();
    table.boolean("show_on_leaderboard").notNullable().defaultTo(false);
    table.boolean("show_on_presence").notNullable().defaultTo(false);
    table.text("presence_label");
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["space_id", "subject_hash"], {
      constraintName: "social_space_profile_settings_pk"
    });
  });

  await knex.schema.createTable("social_space_rituals", (table) => {
    table.uuid("ritual_id").primary();
    table.uuid("space_id").notNullable();
    table.text("ritual_type").notNullable().defaultTo("drop_in_challenge");
    table.text("title").notNullable();
    table.text("description");
    table.text("status").notNullable().defaultTo("ACTIVE");
    table.integer("duration_minutes").notNullable().defaultTo(10);
    table.text("created_by_subject_hash").notNullable();
    table.timestamp("starts_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("ends_at", { useTz: true }).notNullable();
    table.timestamp("closed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["space_id", "status", "starts_at"], "social_space_rituals_space_status_idx");
  });

  await knex.schema.createTable("social_space_ritual_participants", (table) => {
    table.uuid("ritual_id").notNullable();
    table.uuid("space_id").notNullable();
    table.text("subject_hash").notNullable();
    table.timestamp("participated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("completed_at", { useTz: true });
    table.integer("completion_count").notNullable().defaultTo(0);
    table.primary(["ritual_id", "subject_hash"], {
      constraintName: "social_space_ritual_participants_pk"
    });
    table.index(
      ["space_id", "subject_hash", "participated_at"],
      "social_space_ritual_participants_space_subject_idx"
    );
  });

  const actions: Array<[string, string]> = [
    ["presence.ping", "Ping active presence in a social space"],
    ["sync.huddle.create_session", "Create huddle session control-plane"],
    ["sync.huddle.join_session", "Join huddle session control-plane"],
    ["sync.huddle.end_session", "End huddle session control-plane"],
    ["ritual.create", "Create ritual in social space"],
    ["ritual.participate", "Participate in social ritual"],
    ["ritual.complete", "Complete social ritual"],
    ["ritual.end_session", "End social ritual"],
    ["leaderboard.view", "View social contribution leaderboard"]
  ];
  for (const [actionId, description] of actions) {
    await ensureAction(knex, actionId, description);
  }

  await ensureCredentialType(knex, {
    vct: "cuncta.sync.huddle_host",
    json_schema: {
      type: "object",
      properties: {
        huddle_host: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["huddle_host", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["huddle_host", "space_id"],
    display: {
      title: "Huddle Host",
      claims: [
        { path: "huddle_host", label: "Huddle host" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: [
        "sync.huddle.create_session",
        "sync.huddle.end_session",
        "sync.huddle.join_session",
        "sync.session.report"
      ]
    },
    presentation_templates: { required_disclosures: ["huddle_host", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.social.ritual_creator",
    json_schema: {
      type: "object",
      properties: {
        ritual_creator: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["ritual_creator", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["ritual_creator", "space_id"],
    display: {
      title: "Ritual Creator",
      claims: [
        { path: "ritual_creator", label: "Ritual creator" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: ["ritual.create", "ritual.end_session"]
    },
    presentation_templates: { required_disclosures: ["ritual_creator", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await updatePurposeLimits(knex, "cuncta.presence.mode_access", [
    "presence.ping",
    "sync.huddle.join_session"
  ]);
  await updatePurposeLimits(knex, "cuncta.social.space.poster", ["ritual.create"]);
  await updatePurposeLimits(knex, "cuncta.social.space.member", [
    "ritual.participate",
    "ritual.complete"
  ]);

  await upsertPolicy(knex, {
    policy_id: "presence.ping.v1",
    action_id: "presence.ping",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.huddle.create_session.v1",
    action_id: "sync.huddle.create_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.huddle_host",
      ["huddle_host", "space_id"],
      [{ path: "huddle_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.huddle.join_session.v1",
    action_id: "sync.huddle.join_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.huddle.end_session.v1",
    action_id: "sync.huddle.end_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.huddle_host",
      ["huddle_host", "space_id"],
      [{ path: "huddle_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "ritual.create.v1",
    action_id: "ritual.create",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.poster",
      ["poster", "space_id", "tier"],
      [{ path: "poster", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "ritual.participate.v1",
    action_id: "ritual.participate",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "ritual.complete.v1",
    action_id: "ritual.complete",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "ritual.end_session.v1",
    action_id: "ritual.end_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.ritual_creator",
      ["ritual_creator", "space_id"],
      [{ path: "ritual_creator", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "leaderboard.view.v1",
    action_id: "leaderboard.view",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: false },
      requirements: [],
      obligations: []
    }
  });

  await knex("credential_types")
    .whereIn("vct", [
      "cuncta.sync.huddle_host",
      "cuncta.social.ritual_creator",
      "cuncta.social.space.poster",
      "cuncta.social.space.member",
      "cuncta.presence.mode_access"
    ])
    .update({ updated_at: now });
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies")
    .whereIn("action_id", [
      "presence.ping",
      "sync.huddle.create_session",
      "sync.huddle.join_session",
      "sync.huddle.end_session",
      "ritual.create",
      "ritual.participate",
      "ritual.complete",
      "ritual.end_session",
      "leaderboard.view"
    ])
    .del();
  await knex("actions")
    .whereIn("action_id", [
      "presence.ping",
      "sync.huddle.create_session",
      "sync.huddle.join_session",
      "sync.huddle.end_session",
      "ritual.create",
      "ritual.participate",
      "ritual.complete",
      "ritual.end_session",
      "leaderboard.view"
    ])
    .del();
  await knex("credential_types")
    .whereIn("vct", ["cuncta.sync.huddle_host", "cuncta.social.ritual_creator"])
    .del();

  await knex.schema.dropTableIfExists("social_space_ritual_participants");
  await knex.schema.dropTableIfExists("social_space_rituals");
  await knex.schema.dropTableIfExists("social_space_profile_settings");
  await knex.schema.dropTableIfExists("social_space_presence_pings");
}
