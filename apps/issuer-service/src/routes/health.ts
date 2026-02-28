import { FastifyInstance } from "fastify";
import { getDb } from "../db.js";
import { getAnchorWorkerStatus } from "../hedera/anchorWorker.js";
import { metrics } from "../metrics.js";
import { getPepperFingerprint } from "../pseudonymizer.js";
import { config } from "../config.js";
import { getAuditHeadState, getStartupIntegrityFailureCount } from "../audit.js";

export const registerHealthRoutes = (app: FastifyInstance) => {
  app.get("/healthz", async () => {
    let dbOk = true;
    let outboxPending = 0;
    let outboxDead = 0;
    let auditHead = null as string | null;
    let auditAnchoredAt = null as string | null;
    try {
      const db = await getDb();
      await db.raw("select 1");
      const pending = await db("anchor_outbox")
        .where({ status: "PENDING" })
        .count<{ count: string }>("outbox_id as count")
        .first();
      outboxPending = Number(pending?.count ?? 0);
      const dead = await db("anchor_outbox")
        .where({ status: "DEAD" })
        .count<{ count: string }>("outbox_id as count")
        .first();
      outboxDead = Number(dead?.count ?? 0);
      const auditState = await getAuditHeadState();
      auditHead = auditState.headHash;
      auditAnchoredAt = auditState.anchoredAt;
    } catch {
      dbOk = false;
    }
    return {
      ok: dbOk,
      db: { ok: dbOk },
      anchorWorker: getAnchorWorkerStatus(),
      outbox: { pending: outboxPending, dead: outboxDead },
      auditLog: { headHash: auditHead, anchoredAt: auditAnchoredAt },
      pseudonymizer: { fingerprint: getPepperFingerprint() }
    };
  });

  app.get("/metrics", async (_request, reply) => {
    const db = await getDb();
    const anchorStatus = getAnchorWorkerStatus();
    if (anchorStatus.lastRunAt) {
      const unixSeconds = Math.floor(Date.parse(anchorStatus.lastRunAt) / 1000);
      metrics.setGauge("anchor_worker_last_run_at_unix", {}, unixSeconds);
    }
    const outboxRows = (await db("anchor_outbox")
      .select("status", "event_type")
      .count<{ count: string }>("outbox_id as count")
      .groupBy("status", "event_type")) as Array<{
      status: string;
      event_type: string;
      count: string;
    }>;
    let backlogTotal = 0;
    for (const row of outboxRows) {
      metrics.setGauge(
        "outbox_rows_total",
        {
          status: row.status,
          event_type: row.event_type
        },
        Number(row.count ?? 0)
      );
      if (row.status !== "CONFIRMED") {
        backlogTotal += Number(row.count ?? 0);
      }
    }
    metrics.setGauge("anchor_outbox_backlog", {}, backlogTotal);
    const deadRows = outboxRows
      .filter((row) => row.status === "DEAD")
      .reduce((sum, row) => sum + Number(row.count ?? 0), 0);
    metrics.setGauge("anchor_outbox_dead", {}, deadRows);
    metrics.setGauge("backup_restore_mode_active", {}, config.BACKUP_RESTORE_MODE ? 1 : 0);
    metrics.setGauge(
      "startup_integrity_failures_total",
      {},
      await getStartupIntegrityFailureCount()
    );
    reply.header("content-type", "text/plain; version=0.0.4");
    return reply.send(metrics.render());
  });
};
