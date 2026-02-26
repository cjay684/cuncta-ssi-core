import { Knex } from "knex";

export async function up(knex: Knex): Promise<void> {
  await knex.schema.createTable("verification_challenges", (table) => {
    table.text("challenge_id").primary();
    table.text("challenge_hash").notNullable().unique();
    table.text("action_id").notNullable();
    table.timestamp("expires_at", { useTz: true }).notNullable();
    table.timestamp("consumed_at", { useTz: true });
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("rate_limit_events", (table) => {
    table.bigIncrements("id").primary();
    table.text("subject_hash").notNullable();
    table.text("action_id").notNullable();
    table.timestamp("created_at", { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.index(["subject_hash", "action_id", "created_at"]);
  });

  const policy = await knex("policies").where({ policy_id: "marketplace.list_item.v1" }).first();
  if (policy) {
    const logicRaw = policy.logic;
    const logic =
      typeof logicRaw === "string" ? (JSON.parse(logicRaw) as Record<string, unknown>) : logicRaw;
    const obligations = [
      { type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" },
      { type: "RATE_LIMIT", scope: "subject", window_seconds: 60, max: 10 }
    ];
    logic.obligations = logic.obligations ?? obligations;
    if (Array.isArray(logic.requirements)) {
      logic.requirements = logic.requirements.map((req: Record<string, unknown>) => {
        const disclosures = Array.isArray(req.disclosures) ? req.disclosures : [];
        const predicates = Array.isArray(req.predicates) ? req.predicates : [];
        const predicatePaths = predicates
          .map((predicate) => predicate?.path)
          .filter((path) => typeof path === "string") as string[];
        const merged = Array.from(new Set([...disclosures, ...predicatePaths]));
        return { ...req, disclosures: merged };
      });
    }
    await knex("policies")
      .where({ policy_id: "marketplace.list_item.v1" })
      .update({
        logic: JSON.stringify(logic),
        updated_at: new Date().toISOString()
      });
  }
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("rate_limit_events");
  await knex.schema.dropTableIfExists("verification_challenges");
}
