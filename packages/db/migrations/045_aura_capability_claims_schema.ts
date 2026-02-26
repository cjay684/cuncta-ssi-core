import { Knex } from "knex";

const parseJson = (value: unknown): Record<string, unknown> => {
  if (!value) return {};
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  if (typeof value === "object") return value as Record<string, unknown>;
  return {};
};

const toJson = (value: unknown) => JSON.stringify(value);

const PURPOSE_LIMITS_SCHEMA = {
  type: "object",
  properties: {
    actions: { type: "array", items: { type: "string" } }
  },
  required: ["actions"],
  additionalProperties: false
};

export async function up(knex: Knex): Promise<void> {
  const auraVcts = [
    "cuncta.marketplace.seller_good_standing",
    "cuncta.marketplace.trusted_seller_tier",
    "cuncta.social.can_post",
    "cuncta.social.can_comment",
    "cuncta.social.can_follow",
    "cuncta.social.community_member",
    "cuncta.social.trusted_creator",
    "cuncta.social.space.member",
    "cuncta.social.space.poster",
    "cuncta.social.space.moderator",
    "cuncta.social.space.steward"
  ];

  for (const vct of auraVcts) {
    const row = await knex("credential_types").where({ vct }).first();
    if (!row) continue;
    const schema = parseJson((row as { json_schema?: unknown }).json_schema);
    const props = (schema.properties as Record<string, unknown>) ?? {};
    if (!props.purpose) {
      props.purpose = { type: "string" };
    }
    if (!props.purpose_limits) {
      props.purpose_limits = PURPOSE_LIMITS_SCHEMA;
    }
    schema.properties = props;
    // Keep existing required list; do not force purpose fields for backwards compatibility.
    if (schema.additionalProperties === undefined) {
      schema.additionalProperties = false;
    }
    await knex("credential_types")
      .where({ vct })
      .update({ json_schema: toJson(schema), updated_at: new Date().toISOString() });
  }
}

export async function down(knex: Knex): Promise<void> {
  // Non-destructive: leave schema extensions in place.
  void knex;
}

