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

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("social_media_assets", (table) => {
    table.uuid("asset_id").primary();
    table.text("owner_subject_hash").notNullable();
    table.uuid("space_id");
    table.text("media_kind").notNullable().defaultTo("image");
    table.text("storage_provider").notNullable().defaultTo("s3");
    table.text("object_key").notNullable().unique();
    table.text("thumbnail_object_key");
    table.text("mime_type").notNullable();
    table.bigInteger("byte_size").notNullable();
    table.text("sha256_hex").notNullable();
    table.text("status").notNullable().defaultTo("PENDING");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp("finalized_at", { useTz: true });
    table.timestamp("erased_at", { useTz: true });
    table.timestamp("deleted_at", { useTz: true });
    table.index(["owner_subject_hash", "created_at"], "social_media_assets_owner_created_idx");
    table.index(["space_id", "created_at"], "social_media_assets_space_created_idx");
    table.index(["status", "created_at"], "social_media_assets_status_created_idx");
  });

  await knex.schema.createTable("social_realtime_permissions", (table) => {
    table.uuid("permission_id").primary();
    table.text("subject_hash").notNullable();
    table.text("channel").notNullable();
    table.uuid("space_id");
    table.uuid("thread_id");
    table.uuid("session_id");
    table.uuid("challenge_id");
    table.boolean("can_broadcast").notNullable().defaultTo(false);
    table.text("permission_hash").notNullable().unique();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(
      ["space_id", "subject_hash", "channel"],
      "social_realtime_permissions_space_subject_channel_idx"
    );
    table.index(["expires_at"], "social_realtime_permissions_expires_idx");
  });

  await knex.schema.createTable("social_realtime_events", (table) => {
    table.uuid("event_id").primary();
    table.text("channel").notNullable();
    table.uuid("space_id");
    table.uuid("thread_id");
    table.uuid("session_id");
    table.uuid("challenge_id");
    table.text("event_type").notNullable();
    table.jsonb("payload_json").notNullable().defaultTo("{}");
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["channel", "created_at"], "social_realtime_events_channel_created_idx");
    table.index(["space_id", "created_at"], "social_realtime_events_space_created_idx");
  });

  const hasSocialPostImageRefs = await knex.schema.hasColumn("social_posts", "image_refs");
  if (!hasSocialPostImageRefs) {
    await knex.schema.alterTable("social_posts", (table) => {
      table.jsonb("image_refs").notNullable().defaultTo("[]");
    });
  }
  const hasSpacePostImageRefs = await knex.schema.hasColumn("social_space_posts", "image_refs");
  if (!hasSpacePostImageRefs) {
    await knex.schema.alterTable("social_space_posts", (table) => {
      table.jsonb("image_refs").notNullable().defaultTo("[]");
    });
  }

  await ensureAction(knex, "media.image.publish", "Publish image media in social and space posts");
  await ensureAction(
    knex,
    "realtime.channel.broadcast",
    "Broadcast realtime events to authorized social channels"
  );

  await upsertPolicy(knex, {
    policy_id: "media.image.publish.v1",
    action_id: "media.image.publish",
    version: 1,
    logic: {
      binding: { mode: "kb-jwt", require: true },
      requirements: [
        {
          vct: "cuncta.social.space.poster",
          issuer: { mode: "env", env: "ISSUER_DID" },
          disclosures: ["poster", "space_id"],
          predicates: [{ path: "poster", op: "eq", value: true }],
          context_predicates: [{ left: "context.space_id", right: "claims.space_id", op: "eq" }],
          revocation: { required: true }
        }
      ],
      obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
    }
  });
}

export async function down(knex: Knex): Promise<void> {
  const hasSocialPostImageRefs = await knex.schema.hasColumn("social_posts", "image_refs");
  if (hasSocialPostImageRefs) {
    await knex.schema.alterTable("social_posts", (table) => {
      table.dropColumn("image_refs");
    });
  }
  const hasSpacePostImageRefs = await knex.schema.hasColumn("social_space_posts", "image_refs");
  if (hasSpacePostImageRefs) {
    await knex.schema.alterTable("social_space_posts", (table) => {
      table.dropColumn("image_refs");
    });
  }
  await knex("policies")
    .whereIn("action_id", ["media.image.publish", "realtime.channel.broadcast"])
    .del();
  await knex("actions")
    .whereIn("action_id", ["media.image.publish", "realtime.channel.broadcast"])
    .del();
  await knex.schema.dropTableIfExists("social_realtime_events");
  await knex.schema.dropTableIfExists("social_realtime_permissions");
  await knex.schema.dropTableIfExists("social_media_assets");
}
