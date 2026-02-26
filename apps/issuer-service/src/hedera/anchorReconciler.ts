import { randomUUID, createHash } from "node:crypto";
import { fetchTopicMessageBySequence } from "@cuncta/hedera";
import { verifyAnchorMeta } from "@cuncta/shared";
import { config } from "../config.js";
import { getDb } from "../db.js";
import { log } from "../log.js";
import { metrics } from "../metrics.js";

export type AnchorReconciliationStatus =
  | "VERIFIED"
  | "NOT_FOUND"
  | "MISMATCH"
  | "INVALID_AUTH"
  | "ERROR";

type ReceiptRow = {
  payload_hash: string;
  topic_id: string;
  sequence_number: string;
  consensus_timestamp: string;
};

type OutboxRow = {
  payload_hash: string;
  event_type: string;
  payload_meta?: unknown;
};

const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const parseAnchorMessage = (bytes: Uint8Array) => {
  const text = Buffer.from(bytes).toString("utf8");
  const json = JSON.parse(text) as unknown;
  if (!isRecord(json)) {
    throw new Error("mirror_message_not_object");
  }
  return json;
};

const getAuthFields = (meta: unknown) => {
  if (!isRecord(meta)) return {};
  return {
    anchor_auth_sig: meta.anchor_auth_sig,
    anchor_auth_ts: meta.anchor_auth_ts
  };
};

const shouldForceReconcile = (value: unknown) => value === true;

export const reconcileAnchors = async (input?: {
  payloadHashes?: string[];
  limit?: number;
  force?: boolean;
}) => {
  if (!config.ANCHOR_RECONCILIATION_ENABLED) {
    throw new Error("anchor_reconciliation_disabled");
  }

  const db = await getDb();

  const limit = Math.max(1, Math.min(config.ANCHOR_RECONCILE_BATCH_SIZE, input?.limit ?? 3));
  const forced = shouldForceReconcile(input?.force);

  let receipts: ReceiptRow[] = [];
  if (input?.payloadHashes?.length) {
    receipts = (await db("anchor_receipts")
      .whereIn("payload_hash", input.payloadHashes)
      .select("payload_hash", "topic_id", "sequence_number", "consensus_timestamp")) as ReceiptRow[];
  } else {
    // Default: reconcile recent receipts created during normal operation.
    receipts = (await db("anchor_receipts")
      .orderBy("created_at", "desc")
      .limit(limit)
      .select("payload_hash", "topic_id", "sequence_number", "consensus_timestamp")) as ReceiptRow[];
  }

  if (!receipts.length) {
    return { attempted: 0, results: [] as Array<{ status: AnchorReconciliationStatus }> };
  }

  const payloadHashes = receipts.map((r) => r.payload_hash);
  const outboxRows = (await db("anchor_outbox")
    .whereIn("payload_hash", payloadHashes)
    .select("payload_hash", "event_type", "payload_meta")) as OutboxRow[];
  const outboxByHash = new Map(outboxRows.map((row) => [row.payload_hash, row]));

  // If not forced, skip anything already VERIFIED to avoid mirror hammering.
  const existing = (await db("anchor_reconciliations")
    .whereIn("payload_hash", payloadHashes)
    .select("payload_hash", "status")) as Array<{ payload_hash: string; status: string }>;
  const verifiedSet = new Set(
    existing.filter((row) => row.status === "VERIFIED").map((row) => row.payload_hash)
  );
  const candidates = forced ? receipts : receipts.filter((row) => !verifiedSet.has(row.payload_hash));

  const results: Array<{
    payloadHash: string;
    status: AnchorReconciliationStatus;
    reason?: string;
    topicId: string;
    sequenceNumber: number;
  }> = [];

  for (const receipt of candidates) {
    const startedAt = Date.now();
    const topicId = receipt.topic_id;
    const sequenceNumber = Number(receipt.sequence_number);
    const payloadHash = receipt.payload_hash;

    let status: AnchorReconciliationStatus = "ERROR";
    let reason = "unknown";
    let mirrorMessageHash: string | null = null;
    let mirrorMeta: Record<string, unknown> | null = null;

    try {
      const mirrorRes = await fetchTopicMessageBySequence(
        config.MIRROR_NODE_BASE_URL,
        topicId,
        sequenceNumber,
        { timeoutMs: config.ANCHOR_RECONCILE_TIMEOUT_MS, maxAttempts: config.ANCHOR_RECONCILE_MAX_ATTEMPTS }
      );

      if (!mirrorRes.ok) {
        if (mirrorRes.status === 404) {
          status = "NOT_FOUND";
          reason = mirrorRes.error;
        } else {
          status = "ERROR";
          reason = mirrorRes.error;
        }
      } else {
        mirrorMessageHash = sha256Hex(mirrorRes.messageBytes);
        mirrorMeta = {
          consensus_timestamp: mirrorRes.raw.consensus_timestamp,
          sequence_number: mirrorRes.raw.sequence_number,
          topic_id: mirrorRes.raw.topic_id,
          running_hash: mirrorRes.raw.running_hash,
          running_hash_version: mirrorRes.raw.running_hash_version,
          chunk_info: mirrorRes.raw.chunk_info ?? null
        };

        const message = parseAnchorMessage(mirrorRes.messageBytes);
        const mirrorSha = message.sha256;
        const mirrorKind = message.kind;
        const mirrorMetadata = message.metadata;

        if (mirrorSha !== payloadHash) {
          status = "MISMATCH";
          reason = "payload_hash_mismatch";
        } else if (typeof mirrorKind !== "string" || !mirrorKind) {
          status = "MISMATCH";
          reason = "missing_kind";
        } else {
          const outbox = outboxByHash.get(payloadHash);
          if (outbox && outbox.event_type !== mirrorKind) {
            status = "MISMATCH";
            reason = "event_type_mismatch";
          } else {
            const expectedMeta = outbox?.payload_meta;
            const expectedAuth = getAuthFields(expectedMeta);
            const mirrorAuth = getAuthFields(mirrorMetadata);

            // If DB stores auth fields, mirror must match those exact values.
            if (
              expectedAuth.anchor_auth_sig !== undefined &&
              expectedAuth.anchor_auth_ts !== undefined &&
              (mirrorAuth.anchor_auth_sig !== expectedAuth.anchor_auth_sig ||
                mirrorAuth.anchor_auth_ts !== expectedAuth.anchor_auth_ts)
            ) {
              status = "MISMATCH";
              reason = "anchor_auth_expected_mismatch";
            } else if (
              expectedAuth.anchor_auth_sig !== undefined &&
              expectedAuth.anchor_auth_ts !== undefined &&
              (mirrorAuth.anchor_auth_sig === undefined || mirrorAuth.anchor_auth_ts === undefined)
            ) {
              status = "MISMATCH";
              reason = "mirror_missing_anchor_auth_meta";
            } else if (mirrorAuth.anchor_auth_sig !== undefined || mirrorAuth.anchor_auth_ts !== undefined) {
              if (!config.ANCHOR_AUTH_SECRET) {
                status = "ERROR";
                reason = "anchor_auth_secret_missing";
              } else {
                const verified = verifyAnchorMeta(config.ANCHOR_AUTH_SECRET, {
                  payloadHash,
                  eventType: mirrorKind,
                  ...mirrorAuth
                });
                if (verified.ok) {
                  status = "VERIFIED";
                  reason =
                    expectedAuth.anchor_auth_sig === undefined ? "db_missing_anchor_auth_meta" : "ok";
                } else {
                  status = verified.reason === "missing_auth" ? "MISMATCH" : "INVALID_AUTH";
                  reason = `anchor_auth_${verified.reason}`;
                }
              }
            } else {
              // Backward compatibility: historic messages may not contain auth fields.
              status = "VERIFIED";
              reason = "no_anchor_auth_metadata";
            }
          }
        }
      }
    } catch (error) {
      status = "ERROR";
      reason = error instanceof Error ? error.message : "error";
    }

    const rowId = randomUUID();
    const now = new Date().toISOString();
    await db("anchor_reconciliations")
      .insert({
        id: rowId,
        payload_hash: payloadHash,
        topic_id: topicId,
        sequence_number: sequenceNumber,
        consensus_timestamp: receipt.consensus_timestamp,
        verified_at: now,
        status,
        reason,
        mirror_message_hash: mirrorMessageHash,
        mirror_response_meta: mirrorMeta,
        attempts: 1,
        last_attempt_at: now
      })
      .onConflict(["topic_id", "sequence_number"])
      .merge({
        payload_hash: payloadHash,
        verified_at: now,
        status,
        reason,
        mirror_message_hash: mirrorMessageHash,
        mirror_response_meta: mirrorMeta,
        last_attempt_at: now,
        // Preserve attempts count across retries.
        attempts: db.raw("anchor_reconciliations.attempts + 1")
      });

    metrics.incCounter("anchor_reconcile_total", { status }, 1);
    log.info("anchor.reconcile.result", {
      payload_hash_prefix: payloadHash.slice(0, 12),
      topic_id: topicId,
      sequence_number: sequenceNumber,
      status,
      reason,
      elapsed_ms: Date.now() - startedAt
    });

    results.push({ payloadHash, status, reason, topicId, sequenceNumber });
    // Throttle: mirror nodes can be rate limited; keep request rate low.
    await new Promise<void>((resolve) => setTimeout(resolve, 200));
  }

  const counts: Record<string, number> = {};
  for (const r of results) {
    counts[r.status] = (counts[r.status] ?? 0) + 1;
  }
  return { attempted: results.length, counts, results };
};

const withTimeout = async <T>(promise: Promise<T>, timeoutMs: number, errorCode: string): Promise<T> => {
  let timer: NodeJS.Timeout | null = null;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(errorCode)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
};

// Periodic reconciliation is an ops safety net (mirror verification of anchored receipts).
// Safe-by-default: no overlap between runs; low frequency; can be disabled only outside mainnet production.
export const startAnchorReconciler = () => {
  if (!config.ANCHOR_RECONCILIATION_ENABLED) {
    return () => undefined;
  }
  const intervalMs = config.ANCHOR_RECONCILER_POLL_MS;
  let inFlight = false;
  const tick = async () => {
    if (inFlight) return;
    inFlight = true;
    const startedAt = Date.now();
    try {
      await withTimeout(reconcileAnchors(), Math.max(30_000, intervalMs), "reconcile_tick_timeout");
    } catch (error) {
      const message = error instanceof Error ? error.message : "reconcile_tick_failed";
      log.error("anchor.reconcile.tick_failed", { error: message });
    } finally {
      log.info("anchor.reconcile.tick_complete", { elapsed_ms: Date.now() - startedAt });
      inFlight = false;
    }
  };

  void tick();
  const timer = setInterval(() => {
    void tick();
  }, intervalMs);
  return () => clearInterval(timer);
};

