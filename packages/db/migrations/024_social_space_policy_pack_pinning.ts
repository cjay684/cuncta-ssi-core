import { createHash } from "node:crypto";
import { Knex } from "knex";

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

const ensureRequiredDisclosures = (raw: unknown, claims: string[]) => {
  const current = (
    raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {}
  ) as Record<string, unknown>;
  const existing = Array.isArray(current.required_disclosures)
    ? (current.required_disclosures as unknown[]).map((entry) => String(entry))
    : [];
  const merged = Array.from(new Set([...existing, ...claims]));
  return { ...current, required_disclosures: merged };
};

export async function up(knex: Knex): Promise<void> {
  const hasPolicyPackTable = await knex.schema.hasTable("social_space_policy_packs");
  if (!hasPolicyPackTable) return;

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

  const now = new Date().toISOString();
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

  await knex("social_space_policy_packs").where({ policy_pack_id: "space.default.v1" }).update({
    join_policy_hash: joinPolicyHash,
    post_policy_hash: postPolicyHash,
    moderate_policy_hash: moderatePolicyHash,
    pinned_policy_hash_join: joinPolicyHash,
    pinned_policy_hash_post: postPolicyHash,
    pinned_policy_hash_moderate: moderatePolicyHash,
    updated_at: now
  });

  const capabilityVcts = [
    "cuncta.social.space.member",
    "cuncta.social.space.poster",
    "cuncta.social.space.moderator",
    "cuncta.social.space.steward"
  ];
  const rows = await knex("credential_types")
    .whereIn("vct", capabilityVcts)
    .select("vct", "presentation_templates");
  for (const row of rows) {
    const templatesRaw = row.presentation_templates as unknown;
    const templates =
      typeof templatesRaw === "string"
        ? (JSON.parse(templatesRaw) as Record<string, unknown>)
        : (templatesRaw as Record<string, unknown>);
    await knex("credential_types")
      .where({ vct: row.vct })
      .update({
        presentation_templates: ensureRequiredDisclosures(templates, ["space_id"]),
        updated_at: now
      });
  }
}

export async function down(knex: Knex): Promise<void> {
  const hasPolicyPackTable = await knex.schema.hasTable("social_space_policy_packs");
  if (!hasPolicyPackTable) return;
  const hasPinnedJoin = await knex.schema.hasColumn(
    "social_space_policy_packs",
    "pinned_policy_hash_join"
  );
  if (hasPinnedJoin) {
    await knex.schema.alterTable("social_space_policy_packs", (table) => {
      table.dropColumn("pinned_policy_hash_join");
    });
  }
  const hasPinnedPost = await knex.schema.hasColumn(
    "social_space_policy_packs",
    "pinned_policy_hash_post"
  );
  if (hasPinnedPost) {
    await knex.schema.alterTable("social_space_policy_packs", (table) => {
      table.dropColumn("pinned_policy_hash_post");
    });
  }
  const hasPinnedModerate = await knex.schema.hasColumn(
    "social_space_policy_packs",
    "pinned_policy_hash_moderate"
  );
  if (hasPinnedModerate) {
    await knex.schema.alterTable("social_space_policy_packs", (table) => {
      table.dropColumn("pinned_policy_hash_moderate");
    });
  }
}
