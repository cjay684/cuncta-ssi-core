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
  await knex.schema.createTable("sync_sessions", (table) => {
    table.uuid("session_id").primary();
    table.uuid("space_id").notNullable();
    table.text("kind").notNullable();
    table.text("host_subject_did_hash").notNullable();
    table.text("status").notNullable().defaultTo("ACTIVE");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("ended_at", { useTz: true });
    table.text("policy_pack_id");
    table.text("anchor_payload_hash");
    table.index(["space_id", "status", "created_at"], "sync_sessions_space_status_idx");
  });

  await knex.schema.createTable("sync_session_participants", (table) => {
    table.uuid("session_id").notNullable();
    table.text("subject_did_hash").notNullable();
    table.text("role").notNullable().defaultTo("participant");
    table.timestamp("joined_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("left_at", { useTz: true });
    table.primary(["session_id", "subject_did_hash"], {
      constraintName: "sync_session_participants_pk"
    });
    table.index(["session_id", "joined_at"], "sync_session_participants_session_idx");
  });

  await knex.schema.createTable("sync_session_events", (table) => {
    table.uuid("event_id").primary();
    table.uuid("session_id").notNullable();
    table.text("actor_subject_did_hash").notNullable();
    table.text("event_type").notNullable();
    table.jsonb("payload_json").notNullable();
    table.text("payload_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.text("anchored_payload_hash");
    table.index(["session_id", "created_at"], "sync_session_events_session_idx");
    table.index(["created_at"], "sync_session_events_created_idx");
  });

  await knex.schema.createTable("sync_session_reports", (table) => {
    table.uuid("report_id").primary();
    table.uuid("session_id").notNullable();
    table.text("reporter_subject_did_hash").notNullable();
    table.text("reason_code").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["session_id", "created_at"], "sync_session_reports_session_idx");
  });

  await knex.schema.createTable("sync_session_permissions", (table) => {
    table.uuid("permission_id").primary();
    table.uuid("session_id").notNullable();
    table.text("subject_did_hash").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.text("permission_hash").notNullable().unique();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["session_id", "subject_did_hash"], "sync_session_permissions_session_subject_idx");
    table.index(["expires_at"], "sync_session_permissions_expires_idx");
  });

  const actions: Array<[string, string]> = [
    ["sync.scroll.create_session", "Create synchronized scroll session"],
    ["sync.scroll.join_session", "Join synchronized scroll session"],
    ["sync.scroll.sync_event", "Publish synchronized scroll control event"],
    ["sync.scroll.end_session", "End synchronized scroll session"],
    ["sync.listen.create_session", "Create synchronized listen session"],
    ["sync.listen.join_session", "Join synchronized listen session"],
    ["sync.listen.broadcast_control", "Broadcast synchronized listen control event"],
    ["sync.listen.end_session", "End synchronized listen session"],
    ["sync.session.report", "Report synchronized session abuse"],
    ["sync.session.moderate", "Moderate synchronized session"]
  ];
  for (const [actionId, description] of actions) {
    await ensureAction(knex, actionId, description);
  }

  await ensureCredentialType(knex, {
    vct: "cuncta.sync.scroll_host",
    json_schema: {
      type: "object",
      properties: {
        scroll_host: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["scroll_host", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["scroll_host", "space_id"],
    display: {
      title: "Scroll Host",
      claims: [
        { path: "scroll_host", label: "Scroll host" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: ["sync.scroll.create_session", "sync.scroll.end_session", "sync.session.report"]
    },
    presentation_templates: { required_disclosures: ["scroll_host", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.sync.listen_host",
    json_schema: {
      type: "object",
      properties: {
        listen_host: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["listen_host", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["listen_host", "space_id"],
    display: {
      title: "Listen Host",
      claims: [
        { path: "listen_host", label: "Listen host" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: ["sync.listen.create_session", "sync.listen.end_session", "sync.session.report"]
    },
    presentation_templates: { required_disclosures: ["listen_host", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await ensureCredentialType(knex, {
    vct: "cuncta.sync.session_participant",
    json_schema: {
      type: "object",
      properties: {
        participant: { type: "boolean" },
        domain: { type: "string" },
        space_id: { type: "string" },
        as_of: { type: "string", format: "date-time" }
      },
      required: ["participant", "domain", "as_of"],
      additionalProperties: false
    },
    sd_defaults: ["participant", "space_id"],
    display: {
      title: "Sync Session Participant",
      claims: [
        { path: "participant", label: "Session participant" },
        { path: "space_id", label: "Space" }
      ]
    },
    purpose_limits: {
      actions: [
        "sync.scroll.join_session",
        "sync.scroll.sync_event",
        "sync.listen.join_session",
        "sync.listen.broadcast_control"
      ]
    },
    presentation_templates: { required_disclosures: ["participant", "space_id"] },
    revocation_config: { statusPurpose: "revocation", statusListId: "default", bitstringSize: 2048 }
  });

  await upsertPolicy(knex, {
    policy_id: "sync.scroll.create_session.v1",
    action_id: "sync.scroll.create_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.scroll_host",
      ["scroll_host", "space_id"],
      [{ path: "scroll_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.scroll.join_session.v1",
    action_id: "sync.scroll.join_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.scroll.sync_event.v1",
    action_id: "sync.scroll.sync_event",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.scroll.end_session.v1",
    action_id: "sync.scroll.end_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.scroll_host",
      ["scroll_host", "space_id"],
      [{ path: "scroll_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.listen.create_session.v1",
    action_id: "sync.listen.create_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.listen_host",
      ["listen_host", "space_id"],
      [{ path: "listen_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.listen.join_session.v1",
    action_id: "sync.listen.join_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.listen.broadcast_control.v1",
    action_id: "sync.listen.broadcast_control",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.listen.end_session.v1",
    action_id: "sync.listen.end_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.listen_host",
      ["listen_host", "space_id"],
      [{ path: "listen_host", op: "eq", value: true }]
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
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies")
    .whereIn("action_id", [
      "sync.scroll.create_session",
      "sync.scroll.join_session",
      "sync.scroll.sync_event",
      "sync.scroll.end_session",
      "sync.listen.create_session",
      "sync.listen.join_session",
      "sync.listen.broadcast_control",
      "sync.listen.end_session",
      "sync.session.report",
      "sync.session.moderate"
    ])
    .del();

  await knex("actions")
    .whereIn("action_id", [
      "sync.scroll.create_session",
      "sync.scroll.join_session",
      "sync.scroll.sync_event",
      "sync.scroll.end_session",
      "sync.listen.create_session",
      "sync.listen.join_session",
      "sync.listen.broadcast_control",
      "sync.listen.end_session",
      "sync.session.report",
      "sync.session.moderate"
    ])
    .del();

  await knex("credential_types")
    .whereIn("vct", [
      "cuncta.sync.scroll_host",
      "cuncta.sync.listen_host",
      "cuncta.sync.session_participant"
    ])
    .del();

  await knex.schema.dropTableIfExists("sync_session_permissions");
  await knex.schema.dropTableIfExists("sync_session_reports");
  await knex.schema.dropTableIfExists("sync_session_events");
  await knex.schema.dropTableIfExists("sync_session_participants");
  await knex.schema.dropTableIfExists("sync_sessions");
}
