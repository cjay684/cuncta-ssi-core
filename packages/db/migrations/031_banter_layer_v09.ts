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
  await knex.schema.createTable("social_space_banter_threads", (table) => {
    table.uuid("thread_id").primary();
    table.uuid("space_id").notNullable();
    table.text("kind").notNullable();
    table.uuid("crew_id");
    table.uuid("challenge_id");
    table.uuid("hangout_session_id");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("archived_at", { useTz: true });
    table.index(["space_id", "kind"], "social_space_banter_threads_space_kind_idx");
    table.index(["crew_id"], "social_space_banter_threads_crew_idx");
    table.index(["challenge_id"], "social_space_banter_threads_challenge_idx");
    table.index(["hangout_session_id"], "social_space_banter_threads_hangout_idx");
  });

  await knex.schema.createTable("social_banter_messages", (table) => {
    table.uuid("message_id").primary();
    table.uuid("thread_id").notNullable();
    table.text("author_subject_hash").notNullable();
    table.text("body_text");
    table.text("body_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("deleted_at", { useTz: true });
    table.text("visibility").notNullable().defaultTo("normal");
    table.uuid("moderation_case_id");
    table.index(["thread_id", "created_at"], "social_banter_messages_thread_created_idx");
    table.index(["author_subject_hash", "created_at"], "social_banter_messages_author_created_idx");
    table.index(["visibility", "created_at"], "social_banter_messages_visibility_created_idx");
  });

  await knex.schema.createTable("social_presence_status_messages", (table) => {
    table.uuid("status_id").primary();
    table.uuid("space_id").notNullable();
    table.uuid("crew_id");
    table.text("subject_hash").notNullable();
    table.text("status_text").notNullable();
    table.text("status_hash").notNullable();
    table.text("mode").notNullable().defaultTo("active");
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["space_id", "updated_at"], "social_presence_status_messages_space_updated_idx");
    table.index(["crew_id", "updated_at"], "social_presence_status_messages_crew_updated_idx");
    table.index(
      ["space_id", "subject_hash", "crew_id"],
      "social_presence_status_messages_space_subject_crew_idx"
    );
  });

  await knex.schema.createTable("social_banter_reactions", (table) => {
    table.uuid("message_id").notNullable();
    table.text("reactor_subject_hash").notNullable();
    table.uuid("emoji_id");
    table.text("emoji_shortcode");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["message_id", "reactor_subject_hash"], {
      constraintName: "social_banter_reactions_pk"
    });
    table.index(["message_id", "created_at"], "social_banter_reactions_message_created_idx");
  });

  await knex.schema.createTable("social_banter_permissions", (table) => {
    table.uuid("permission_id").primary();
    table.uuid("thread_id").notNullable();
    table.text("subject_hash").notNullable();
    table.text("permission_hash").notNullable().unique();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["thread_id", "subject_hash"], "social_banter_permissions_thread_subject_idx");
  });

  const actions: Array<[string, string]> = [
    ["banter.thread.create", "Create banter thread in a space"],
    ["banter.thread.read", "Read banter thread in a space"],
    ["banter.message.send", "Send banter message in a thread"],
    ["banter.message.react", "React to banter message"],
    ["banter.message.delete_own", "Delete own banter message"],
    ["banter.message.moderate", "Moderate banter message in a space"],
    ["banter.status.set", "Set scoped status message in space or crew"]
  ];
  for (const [actionId, description] of actions) {
    await ensureAction(knex, actionId, description);
  }

  await updatePurposeLimits(knex, "cuncta.social.space.member", [
    "banter.thread.read",
    "banter.thread.create",
    "banter.message.send",
    "banter.message.react",
    "banter.message.delete_own"
  ]);
  await updatePurposeLimits(knex, "cuncta.social.space.moderator", ["banter.message.moderate"]);
  await updatePurposeLimits(knex, "cuncta.presence.mode_access", ["banter.status.set"]);

  await upsertPolicy(knex, {
    policy_id: "banter.thread.create.v1",
    action_id: "banter.thread.create",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "banter.thread.read.v1",
    action_id: "banter.thread.read",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "banter.message.send.v1",
    action_id: "banter.message.send",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "banter.message.react.v1",
    action_id: "banter.message.react",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "banter.message.delete_own.v1",
    action_id: "banter.message.delete_own",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "banter.message.moderate.v1",
    action_id: "banter.message.moderate",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.moderator",
      ["moderator", "space_id"],
      [{ path: "moderator", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "banter.status.set.v1",
    action_id: "banter.status.set",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies")
    .whereIn("action_id", [
      "banter.thread.create",
      "banter.thread.read",
      "banter.message.send",
      "banter.message.react",
      "banter.message.delete_own",
      "banter.message.moderate",
      "banter.status.set"
    ])
    .del();
  await knex("actions")
    .whereIn("action_id", [
      "banter.thread.create",
      "banter.thread.read",
      "banter.message.send",
      "banter.message.react",
      "banter.message.delete_own",
      "banter.message.moderate",
      "banter.status.set"
    ])
    .del();
  await knex.schema.dropTableIfExists("social_banter_permissions");
  await knex.schema.dropTableIfExists("social_banter_reactions");
  await knex.schema.dropTableIfExists("social_presence_status_messages");
  await knex.schema.dropTableIfExists("social_banter_messages");
  await knex.schema.dropTableIfExists("social_space_banter_threads");
}
