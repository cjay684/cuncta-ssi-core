import { buildHederaClient, ensureTopic, publishAnchorMessage } from "@cuncta/hedera";
import { config } from "../config.js";
import { getDb } from "../db.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { markAuditHeadAnchored } from "../audit.js";

const resolveAnchorOperator = () => {
  const operatorId =
    config.HEDERA_OPERATOR_ID_ANCHOR ??
    (config.ALLOW_LEGACY_OPERATOR_KEYS ? config.HEDERA_OPERATOR_ID : undefined);
  const operatorKey =
    config.HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR ??
    (config.ALLOW_LEGACY_OPERATOR_KEYS ? config.HEDERA_OPERATOR_PRIVATE_KEY : undefined);
  if (!operatorId || !operatorKey) {
    return null;
  }
  return { operatorId, operatorKey };
};

const getClient = async () => {
  const operator = resolveAnchorOperator();
  if (!operator) {
    return null;
  }
  const client = buildHederaClient(
    config.HEDERA_NETWORK,
    operator.operatorId,
    operator.operatorKey
  );
  const topicId = await ensureTopic(client, config.HEDERA_ANCHOR_TOPIC_ID || undefined);
  return { client, topicId };
};

const backoffMs = (attempts: number) => Math.min(60_000, 1000 * 2 ** attempts);

const workerStatus = {
  lastRunAt: null as string | null,
  lastError: null as string | null
};

export const getAnchorWorkerStatus = () => ({ ...workerStatus });

type AnchorReceipt = {
  topicId: string;
  sequenceNumber: string;
  consensusTimestamp: string;
};

type AnchorOutboxRow = {
  outbox_id: string;
  payload_hash: string;
  payload_meta?: unknown;
  event_type: string;
  status: string;
  attempts?: number | string | null;
};

export const processAnchorOutboxOnce = async (
  publisher?: (row: AnchorOutboxRow) => Promise<AnchorReceipt>
) => {
  const now = new Date().toISOString();
  workerStatus.lastRunAt = now;
  workerStatus.lastError = null;
  let db: Awaited<ReturnType<typeof getDb>>;
  try {
    db = await getDb();
  } catch (error) {
    workerStatus.lastError = error instanceof Error ? error.message : "db_unavailable";
    throw error;
  }
  const staleBefore = new Date(
    Date.now() - config.ANCHOR_OUTBOX_PROCESSING_TIMEOUT_MS
  ).toISOString();
  await db("anchor_outbox")
    .where({ status: "PROCESSING" })
    .andWhere((builder) => {
      builder.whereNull("processing_started_at").orWhere("processing_started_at", "<", staleBefore);
    })
    .update({
      status: "PENDING",
      processing_started_at: null,
      updated_at: new Date().toISOString()
    });
  const rows = await db("anchor_outbox")
    .whereIn("status", ["PENDING", "FAILED"])
    .andWhere("next_retry_at", "<=", now)
    .orderBy("created_at", "asc")
    .limit(config.OUTBOX_BATCH_SIZE);

  if (!rows.length) {
    metrics.incCounter("worker_runs_total", {
      worker: "anchor",
      status: "success"
    });
    return;
  }

  const clientInfo = publisher ? null : await getClient();
  let hadError = false;
  const markDead = async (row: AnchorOutboxRow, reason: string, attempts: number) => {
    await db("anchor_outbox").where({ outbox_id: row.outbox_id }).update({
      status: "DEAD",
      attempts,
      next_retry_at: new Date().toISOString(),
      processing_started_at: null,
      updated_at: new Date().toISOString()
    });
    metrics.incCounter("anchor_outbox_dead_total");
    workerStatus.lastError = reason;
    log.error("anchor.worker.dead_lettered", { outboxId: row.outbox_id, reason });
  };
  for (const row of rows as AnchorOutboxRow[]) {
    const attemptCount = Number(row.attempts ?? 0);
    const nextAttemptAt = new Date(Date.now() + backoffMs(attemptCount + 1)).toISOString();
    if (attemptCount >= config.ANCHOR_MAX_ATTEMPTS) {
      hadError = true;
      await markDead(row, "max_attempts_exceeded", attemptCount);
      continue;
    }
    if (!publisher && !clientInfo) {
      hadError = true;
      workerStatus.lastError = "operator_not_configured";
      await db("anchor_outbox")
        .where({ outbox_id: row.outbox_id })
        .update({
          status: "FAILED",
          attempts: attemptCount + 1,
          next_retry_at: nextAttemptAt,
          updated_at: new Date().toISOString()
        });
      continue;
    }

    const updated = await db("anchor_outbox")
      .where({ outbox_id: row.outbox_id })
      .andWhere("status", row.status)
      .update({
        status: "PROCESSING",
        processing_started_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    if (!updated) {
      continue;
    }

    try {
      const alreadyAnchored = await db("anchor_receipts")
        .where({ payload_hash: row.payload_hash })
        .first();
      if (alreadyAnchored) {
        await db("anchor_outbox").where({ outbox_id: row.outbox_id }).update({
          status: "CONFIRMED",
          processing_started_at: null,
          updated_at: new Date().toISOString()
        });
        if (row.event_type === "AUDIT_LOG_HEAD") {
          await markAuditHeadAnchored(row.payload_hash);
        }
        continue;
      }

      const payloadMeta = (row.payload_meta ?? {}) as Record<string, unknown>;
      const anchor = publisher
        ? await publisher(row)
        : await publishAnchorMessage(clientInfo!.client, clientInfo!.topicId, {
            kind: row.event_type,
            sha256: row.payload_hash,
            metadata: payloadMeta
          });

      await db("anchor_receipts")
        .insert({
          payload_hash: row.payload_hash,
          topic_id: anchor.topicId,
          sequence_number: anchor.sequenceNumber,
          consensus_timestamp: anchor.consensusTimestamp,
          created_at: new Date().toISOString()
        })
        .onConflict("payload_hash")
        .ignore();

      await db("anchor_outbox").where({ outbox_id: row.outbox_id }).update({
        status: "CONFIRMED",
        processing_started_at: null,
        updated_at: new Date().toISOString()
      });

      if (row.event_type === "AUDIT_LOG_HEAD") {
        await markAuditHeadAnchored(row.payload_hash);
      }
    } catch (error) {
      hadError = true;
      const message = error instanceof Error ? error.message : "anchor_failed";
      workerStatus.lastError = message;
      if (attemptCount + 1 >= config.ANCHOR_MAX_ATTEMPTS) {
        await db("anchor_outbox")
          .where({ outbox_id: row.outbox_id })
          .update({
            status: "DEAD",
            attempts: attemptCount + 1,
            next_retry_at: new Date().toISOString(),
            processing_started_at: null,
            updated_at: new Date().toISOString()
          });
        metrics.incCounter("anchor_outbox_dead_total");
        log.error("anchor.worker.dead_lettered", {
          outboxId: row.outbox_id,
          reason: message
        });
      } else {
        await db("anchor_outbox")
          .where({ outbox_id: row.outbox_id })
          .update({
            status: "FAILED",
            attempts: attemptCount + 1,
            next_retry_at: nextAttemptAt,
            processing_started_at: null,
            updated_at: new Date().toISOString()
          });
        log.warn("anchor.worker.failed", { error: message, eventType: row.event_type });
      }
    }
  }
  metrics.incCounter("worker_runs_total", {
    worker: "anchor",
    status: hadError ? "failed" : "success"
  });
  if (hadError) {
    metrics.incCounter("anchor_worker_error_total");
  }
};

export const startAnchorWorker = (options?: { process?: () => Promise<void> }) => {
  const intervalMs = config.ANCHOR_WORKER_POLL_MS;
  const runProcess = options?.process ?? processAnchorOutboxOnce;
  let inFlight = false;
  let lastSkipLogAt = 0;
  const tick = async () => {
    if (inFlight) {
      const now = Date.now();
      if (now - lastSkipLogAt >= intervalMs) {
        lastSkipLogAt = now;
        log.warn("anchor.worker.skip", { reason: "in_flight" });
      }
      return;
    }
    inFlight = true;
    try {
      await runProcess();
    } finally {
      inFlight = false;
    }
  };

  tick().catch((error) => log.error("anchor.worker.tick_failed", { error }));
  const timer = setInterval(() => {
    tick().catch((error) => log.error("anchor.worker.tick_failed", { error }));
  }, intervalMs);

  return () => clearInterval(timer);
};
