import { FastifyInstance } from "fastify";
import { metrics } from "../metrics.js";
import { getSponsorBudgetSnapshot } from "../sponsorBudget.js";
import { config } from "../config.js";

export const registerMetricsRoutes = (app: FastifyInstance) => {
  app.get("/metrics", async (_request, reply) => {
    let budget = null as Awaited<ReturnType<typeof getSponsorBudgetSnapshot>> | null;
    try {
      budget = await getSponsorBudgetSnapshot();
    } catch {
      budget = null;
    }
    if (budget) {
      const remainingDidCreates = Math.max(
        budget.limits.didCreatesPerDay - budget.didCreatesCount,
        0
      );
      const remainingIssues = Math.max(budget.limits.issuesPerDay - budget.issuesCount, 0);
      metrics.setGauge("sponsor_budget_remaining", { kind: "did_create" }, remainingDidCreates);
      metrics.setGauge("sponsor_budget_remaining", { kind: "issue" }, remainingIssues);
      metrics.setGauge(
        "sponsor_budget_consumed_today",
        { kind: "did_create" },
        budget.didCreatesCount
      );
      metrics.setGauge("sponsor_budget_consumed_today", { kind: "issue" }, budget.issuesCount);
    }
    metrics.setGauge("sponsor_kill_switch_active", {}, config.SPONSOR_KILL_SWITCH ? 1 : 0);
    metrics.setGauge("backup_restore_mode_active", {}, config.BACKUP_RESTORE_MODE ? 1 : 0);
    reply.header("content-type", "text/plain; version=0.0.4");
    return metrics.render();
  });
};
