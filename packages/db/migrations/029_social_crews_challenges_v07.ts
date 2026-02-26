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
  await knex.schema.createTable("social_space_crews", (table) => {
    table.uuid("crew_id").primary();
    table.uuid("space_id").notNullable();
    table.text("name").notNullable();
    table.text("created_by_subject_hash").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("archived_at", { useTz: true });
    table.index(["space_id", "created_at"], "social_space_crews_space_created_idx");
  });

  await knex.schema.createTable("social_space_crew_members", (table) => {
    table.uuid("crew_id").notNullable();
    table.text("subject_hash").notNullable();
    table.text("role").notNullable().defaultTo("member");
    table.timestamp("joined_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("left_at", { useTz: true });
    table.primary(["crew_id", "subject_hash"], { constraintName: "social_space_crew_members_pk" });
    table.index(["crew_id", "left_at"], "social_space_crew_members_crew_left_idx");
  });

  await knex.schema.createTable("social_space_challenges", (table) => {
    table.uuid("challenge_id").primary();
    table.uuid("space_id").notNullable();
    table.text("cadence").notNullable().defaultTo("ad_hoc");
    table.text("title").notNullable();
    table.timestamp("starts_at", { useTz: true }).notNullable();
    table.timestamp("ends_at", { useTz: true }).notNullable();
    table.text("created_by_subject_hash").notNullable();
    table.text("status").notNullable().defaultTo("ACTIVE");
    table.uuid("crew_id");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("ended_at", { useTz: true });
    table.index(["space_id", "status", "starts_at"], "social_space_challenges_space_status_idx");
  });

  await knex.schema.createTable("social_space_challenge_participation", (table) => {
    table.uuid("challenge_id").notNullable();
    table.text("subject_hash").notNullable();
    table.timestamp("joined_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("completed_at", { useTz: true });
    table.bigInteger("evidence_action_log_id");
    table.primary(["challenge_id", "subject_hash"], {
      constraintName: "social_space_challenge_participation_pk"
    });
    table.index(
      ["challenge_id", "completed_at"],
      "social_space_challenge_participation_challenge_completed_idx"
    );
  });

  await knex.schema.createTable("social_space_streaks", (table) => {
    table.uuid("space_id").notNullable();
    table.text("subject_hash").notNullable();
    table.text("streak_type").notNullable();
    table.integer("current_count").notNullable().defaultTo(0);
    table.integer("best_count").notNullable().defaultTo(0);
    table.timestamp("last_completed_at", { useTz: true });
    table.timestamp("updated_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.primary(["space_id", "subject_hash", "streak_type"], {
      constraintName: "social_space_streaks_pk"
    });
    table.index(
      ["space_id", "streak_type", "current_count"],
      "social_space_streaks_space_type_idx"
    );
  });

  const actions: Array<[string, string]> = [
    ["social.crew.create", "Create crew in social space"],
    ["social.crew.join", "Join crew in social space"],
    ["social.crew.invite", "Invite member into crew"],
    ["social.crew.leave", "Leave crew in social space"],
    ["challenge.create", "Create recurring challenge in social space"],
    ["challenge.join", "Join recurring challenge in social space"],
    ["challenge.complete", "Complete recurring challenge in social space"],
    ["challenge.end", "End recurring challenge in social space"],
    ["sync.hangout.create_session", "Create hangout session control-plane"],
    ["sync.hangout.join_session", "Join hangout session control-plane"],
    ["sync.hangout.end_session", "End hangout session control-plane"]
  ];
  for (const [actionId, description] of actions) {
    await ensureAction(knex, actionId, description);
  }

  await updatePurposeLimits(knex, "cuncta.social.space.member", [
    "social.crew.join",
    "social.crew.invite",
    "social.crew.leave",
    "challenge.join",
    "challenge.complete"
  ]);
  await updatePurposeLimits(knex, "cuncta.social.space.poster", ["social.crew.create"]);
  await updatePurposeLimits(knex, "cuncta.social.space.moderator", [
    "social.crew.create",
    "social.crew.invite",
    "challenge.end"
  ]);
  await updatePurposeLimits(knex, "cuncta.social.space.steward", ["challenge.create"]);
  await updatePurposeLimits(knex, "cuncta.sync.huddle_host", [
    "sync.hangout.create_session",
    "sync.hangout.end_session",
    "sync.hangout.join_session"
  ]);
  await updatePurposeLimits(knex, "cuncta.presence.mode_access", ["sync.hangout.join_session"]);

  await upsertPolicy(knex, {
    policy_id: "social.crew.create.v1",
    action_id: "social.crew.create",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.poster",
      ["poster", "space_id"],
      [{ path: "poster", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "social.crew.join.v1",
    action_id: "social.crew.join",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "social.crew.invite.v1",
    action_id: "social.crew.invite",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "social.crew.leave.v1",
    action_id: "social.crew.leave",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: false },
      requirements: [],
      obligations: []
    }
  });
  await upsertPolicy(knex, {
    policy_id: "challenge.create.v1",
    action_id: "challenge.create",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.steward",
      ["steward", "space_id"],
      [{ path: "steward", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "challenge.join.v1",
    action_id: "challenge.join",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "challenge.complete.v1",
    action_id: "challenge.complete",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.member",
      ["member", "space_id"],
      [{ path: "member", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "challenge.end.v1",
    action_id: "challenge.end",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.social.space.moderator",
      ["moderator", "space_id"],
      [{ path: "moderator", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.hangout.create_session.v1",
    action_id: "sync.hangout.create_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.huddle_host",
      ["huddle_host", "space_id"],
      [{ path: "huddle_host", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.hangout.join_session.v1",
    action_id: "sync.hangout.join_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.presence.mode_access",
      ["mode_access", "space_id"],
      [{ path: "mode_access", op: "eq", value: true }]
    )
  });
  await upsertPolicy(knex, {
    policy_id: "sync.hangout.end_session.v1",
    action_id: "sync.hangout.end_session",
    version: 1,
    logic: withSpaceBinding(
      "cuncta.sync.huddle_host",
      ["huddle_host", "space_id"],
      [{ path: "huddle_host", op: "eq", value: true }]
    )
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex("policies")
    .whereIn("action_id", [
      "social.crew.create",
      "social.crew.join",
      "social.crew.invite",
      "social.crew.leave",
      "challenge.create",
      "challenge.join",
      "challenge.complete",
      "challenge.end",
      "sync.hangout.create_session",
      "sync.hangout.join_session",
      "sync.hangout.end_session"
    ])
    .del();

  await knex("actions")
    .whereIn("action_id", [
      "social.crew.create",
      "social.crew.join",
      "social.crew.invite",
      "social.crew.leave",
      "challenge.create",
      "challenge.join",
      "challenge.complete",
      "challenge.end",
      "sync.hangout.create_session",
      "sync.hangout.join_session",
      "sync.hangout.end_session"
    ])
    .del();

  await knex.schema.dropTableIfExists("social_space_streaks");
  await knex.schema.dropTableIfExists("social_space_challenge_participation");
  await knex.schema.dropTableIfExists("social_space_challenges");
  await knex.schema.dropTableIfExists("social_space_crew_members");
  await knex.schema.dropTableIfExists("social_space_crews");
}
