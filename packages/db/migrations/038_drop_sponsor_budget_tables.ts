import { Knex } from "knex";

// Self-funded onboarding only: sponsor budget tables are legacy and should not
// exist in new deployments (mainnet readiness).
export async function up(knex: Knex): Promise<void> {
  await knex.schema.dropTableIfExists("sponsor_budget_events");
  await knex.schema.dropTableIfExists("sponsor_budget_daily");
}

export async function down(knex: Knex): Promise<void> {
  // No-op: do not recreate deprecated tables.
}

