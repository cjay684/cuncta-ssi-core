import { randomUUID } from "node:crypto";
import { signAnchorMeta } from "@cuncta/shared";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { getAuditHeadState } from "../audit.js";

const workerStatus = {
  lastRunAt: null as string | null,
  lastError: null as string | null
};

export const getCleanupWorkerStatus = () => ({ ...workerStatus });

const daysAgo = (days: number) => new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();

const enqueueAuditHeadAnchor = async () => {
  const { headHash, anchoredHash } = await getAuditHeadState();
  if (!headHash || headHash === anchoredHash) {
    return;
  }
  if (!config.ANCHOR_AUTH_SECRET) {
    throw new Error("anchor_auth_secret_missing");
  }
  const db = await getDb();
  await db("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: "AUDIT_LOG_HEAD",
      payload_hash: headHash,
      payload_meta: signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
        payloadHash: headHash,
        eventType: "AUDIT_LOG_HEAD"
      }),
      status: "PENDING",
      attempts: 0,
      next_retry_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .onConflict("payload_hash")
    .ignore();
};

export const runCleanupOnce = async () => {
  const db = await getDb();
  const now = new Date().toISOString();
  workerStatus.lastRunAt = now;
  workerStatus.lastError = null;

  const cutoffChallenges = daysAgo(config.RETENTION_VERIFICATION_CHALLENGES_DAYS);
  const cutoffRateLimits = daysAgo(config.RETENTION_RATE_LIMIT_EVENTS_DAYS);
  const cutoffObligations = daysAgo(config.RETENTION_OBLIGATION_EVENTS_DAYS);
  const cutoffAura = daysAgo(config.RETENTION_AURA_SIGNALS_DAYS);
  const cutoffAudit = daysAgo(config.RETENTION_AUDIT_LOGS_DAYS);

  const challengesDeleted = await db("verification_challenges")
    .where((builder) => {
      builder
        .whereNotNull("consumed_at")
        .andWhere("consumed_at", "<", cutoffChallenges)
        .orWhere("expires_at", "<", cutoffChallenges);
    })
    .del();

  const rateLimitsDeleted = await db("rate_limit_events")
    .where("created_at", "<", cutoffRateLimits)
    .del();

  const obligationsDeleted = await db("obligation_events")
    .where("created_at", "<", cutoffObligations)
    .del();

  const auraSignalsDeleted = await db("aura_signals").where("created_at", "<", cutoffAura).del();

  const auditDeleted = await db("audit_logs").where("created_at", "<", cutoffAudit).del();

  await enqueueAuditHeadAnchor();

  log.info("cleanup.worker.run", {
    challengesDeleted,
    rateLimitsDeleted,
    obligationsDeleted,
    auraSignalsDeleted,
    auditDeleted
  });
};

export const startCleanupWorker = () => {
  const tick = async () => {
    try {
      await runCleanupOnce();
      metrics.incCounter("worker_runs_total", { worker: "cleanup", status: "success" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "cleanup_failed";
      workerStatus.lastError = message;
      metrics.incCounter("worker_runs_total", { worker: "cleanup", status: "failed" });
      log.error("cleanup.worker.failed", { error: message });
    }
  };
  void tick();
  return setInterval(tick, config.CLEANUP_WORKER_POLL_MS);
};
