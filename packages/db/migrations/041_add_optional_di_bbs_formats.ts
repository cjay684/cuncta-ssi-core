import { Knex } from "knex";

type PolicyRequirement = {
  formats?: string[];
  [key: string]: unknown;
};

type PolicyLogic = {
  requirements?: PolicyRequirement[];
  [key: string]: unknown;
};

const addFormatToRequirement = (logic: PolicyLogic): PolicyLogic => {
  if (!logic || typeof logic !== "object") return logic;
  const reqs = Array.isArray(logic.requirements) ? logic.requirements : [];
  const nextReqs = reqs.map((r): PolicyRequirement => {
    if (!r || typeof r !== "object") return r;
    const formats = Array.isArray(r.formats) ? r.formats.map(String) : ["dc+sd-jwt"];
    if (!formats.includes("dc+sd-jwt")) formats.push("dc+sd-jwt");
    if (!formats.includes("di+bbs")) formats.push("di+bbs");
    return { ...r, formats };
  });
  return { ...logic, requirements: nextReqs };
};

export async function up(knex: Knex): Promise<void> {
  const policies = await knex("policies")
    .whereIn("policy_id", ["marketplace.list_item.v1", "marketplace.list_high_value.v1"])
    .select("policy_id", "logic");

  for (const row of policies) {
    const raw = row.logic as unknown;
    const logic = (typeof raw === "string" ? JSON.parse(raw) : raw) as PolicyLogic;
    const next = addFormatToRequirement(logic);
    await knex("policies")
      .where({ policy_id: row.policy_id })
      .update({
        logic: JSON.stringify(next),
        updated_at: new Date().toISOString()
      });
  }
}

export async function down(knex: Knex): Promise<void> {
  // Non-destructive: keep formats if already present.
  void knex;
}
