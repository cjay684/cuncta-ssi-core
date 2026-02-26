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
  const cutoffAuraState = daysAgo(config.RETENTION_AURA_STATE_DAYS);
  const cutoffAuraQueue = daysAgo(config.RETENTION_AURA_ISSUANCE_QUEUE_DAYS);
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

  // Capability state minimization: remove stale state and terminal queue rows.
  // - `aura_state` is re-derivable from recent signals; keep bounded to reduce long-lived profiling risk.
  const auraStateDeleted = await db("aura_state").where("updated_at", "<", cutoffAuraState).del();

  // - Queue: keep only active work items; drop old terminal rows.
  const auraQueueDeleted = await db("aura_issuance_queue")
    .whereIn("status", ["ISSUED", "FAILED"])
    .andWhere((builder) => {
      builder.where("updated_at", "<", cutoffAuraQueue).orWhere("issued_at", "<", cutoffAuraQueue);
    })
    .del()
    .catch(() => 0);

  const auditDeleted = await db("audit_logs").where("created_at", "<", cutoffAudit).del();

  // OID4VCI short-lived state: delete expired/consumed (hash-only, no subject linkage).
  // Keep conservative defaults: anything expired is safe to delete; consumed entries are also deletable.
  const oid4vciCodesDeleted = await db("oid4vci_preauth_codes")
    .where((builder) => {
      builder.whereNotNull("consumed_at").orWhere("expires_at", "<", now);
    })
    .del()
    .catch(() => 0);

  const oid4vciNoncesDeleted = await db("oid4vci_c_nonces")
    .where((builder) => {
      builder.whereNotNull("consumed_at").orWhere("expires_at", "<", now);
    })
    .del()
    .catch(() => 0);

  // OID4VCI offer challenge nonces (hash-only, no subject linkage).
  const oid4vciOfferChallengesDeleted = await db("oid4vci_offer_challenges")
    .where((builder) => {
      builder.whereNotNull("consumed_at").orWhere("expires_at", "<", now);
    })
    .del()
    .catch(() => 0);

  await enqueueAuditHeadAnchor();

  log.info("cleanup.worker.run", {
    challengesDeleted,
    rateLimitsDeleted,
    obligationsDeleted,
    auraSignalsDeleted,
    auraStateDeleted,
    auraQueueDeleted,
    auditDeleted,
    oid4vciCodesDeleted,
    oid4vciNoncesDeleted,
    oid4vciOfferChallengesDeleted
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
