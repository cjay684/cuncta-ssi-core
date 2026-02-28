import { randomUUID } from "node:crypto";
import { getDb } from "../db.js";
import { hashCanonicalJson } from "@cuncta/shared";
import { sha256Hex } from "../crypto/sha256.js";
const shouldRun = (decision, when) => {
  if (!when || when === "ON_ALLOW") {
    return decision === "ALLOW";
  }
  if (when === "ON_DENY") {
    return decision === "DENY";
  }
  if (when === "ALWAYS") {
    return true;
  }
  return decision === "ALLOW";
};
const insertAnchorOutbox = async (payloadHash, eventType, payloadMeta) => {
  const db = await getDb();
  await db("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: eventType,
      payload_hash: payloadHash,
      payload_meta: payloadMeta,
      status: "PENDING",
      attempts: 0,
      next_retry_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .onConflict("payload_hash")
    .ignore();
};
const recordRateLimit = async (subjectHash, actionId, windowSeconds, max) => {
  const db = await getDb();
  const since = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const countRow = await db("rate_limit_events")
    .where({ subject_hash: subjectHash, action_id: actionId })
    .andWhere("created_at", ">=", since)
    .count("id as count")
    .first();
  const count = Number(countRow?.count ?? 0);
  if (count >= max) {
    return { allowed: false };
  }
  await db("rate_limit_events").insert({
    subject_hash: subjectHash,
    action_id: actionId,
    created_at: new Date().toISOString()
  });
  return { allowed: true };
};
const recordEmitEvent = async (input) => {
  const db = await getDb();
  const eventPayload = {
    event: input.eventType,
    actionId: input.actionId,
    subjectDidHash: input.subjectDidHash,
    tokenHash: input.tokenHash,
    challengeHash: input.challengeHash,
    occurredAt: new Date().toISOString()
  };
  const eventHash = hashCanonicalJson(eventPayload);
  await db("obligation_events")
    .insert({
      action_id: input.actionId,
      event_type: input.eventType,
      subject_did_hash: input.subjectDidHash,
      token_hash: input.tokenHash,
      challenge_hash: input.challengeHash,
      event_hash: eventHash,
      created_at: new Date().toISOString()
    })
    .onConflict("event_hash")
    .ignore();
};
export const executeObligations = async (input) => {
  const db = await getDb();
  const now = new Date().toISOString();
  const obligationsHash = hashCanonicalJson(input.obligations);
  // Idempotency key: a challenge nonce + policy version + decision must only execute once.
  // This prevents duplicate side-effects under retries/concurrent verify calls.
  const executionPayload = {
    actionId: input.actionId,
    policyId: input.policyId,
    policyVersion: input.policyVersion,
    decision: input.decision,
    subjectDidHash: input.subjectDidHash,
    tokenHash: input.tokenHash,
    challengeHash: input.challengeHash,
    obligationsHash,
    executedAt: now
  };
  const anchorPayloadHash = hashCanonicalJson(executionPayload);
  const executionId = `obl_${randomUUID()}`;
  const { inserted, executionRow } = await db.transaction(async (trx) => {
    const insertedRows = await trx("obligations_executions")
      .insert({
        id: executionId,
        action_id: input.actionId,
        policy_id: input.policyId,
        policy_version: input.policyVersion,
        decision: input.decision,
        subject_did_hash: input.subjectDidHash,
        token_hash: input.tokenHash,
        challenge_hash: input.challengeHash,
        obligations_hash: obligationsHash,
        executed_at: now,
        anchor_payload_hash: anchorPayloadHash,
        status: "PENDING"
      })
      .onConflict(["challenge_hash", "action_id", "policy_id", "policy_version", "decision"])
      .ignore()
      .returning(["id"]);
    if (insertedRows.length > 0) {
      return { inserted: true, executionRow: { id: insertedRows[0].id } };
    }
    const existing = await trx("obligations_executions")
      .where({
        challenge_hash: input.challengeHash,
        action_id: input.actionId,
        policy_id: input.policyId,
        policy_version: input.policyVersion,
        decision: input.decision
      })
      .first();
    return { inserted: false, executionRow: existing };
  });
  const finalExecutionId = executionRow?.id ?? executionId;
  if (!inserted) {
    return {
      executionId: finalExecutionId,
      obligations: (input.obligations ?? []).map((obligation) => ({
        type: obligation.type,
        status: "SKIPPED"
      }))
    };
  }
  const results = [];
  let blockedReason;
  try {
    await insertAnchorOutbox(anchorPayloadHash, "OBLIGATION_EXECUTED", {
      action_id_hash: sha256Hex(input.actionId),
      policy_id_hash: sha256Hex(input.policyId),
      policy_version: input.policyVersion,
      decision: input.decision,
      execution_id_hash: sha256Hex(finalExecutionId)
    });
    for (const obligation of input.obligations ?? []) {
      if (!shouldRun(input.decision, obligation.when)) {
        results.push({ type: obligation.type, status: "SKIPPED" });
        continue;
      }
      if (obligation.type === "RATE_LIMIT") {
        const windowSeconds =
          typeof obligation.window_seconds === "number" ? obligation.window_seconds : 60;
        const max = typeof obligation.max === "number" ? obligation.max : 10;
        const rate = await recordRateLimit(
          input.subjectDidHash,
          input.actionId,
          windowSeconds,
          max
        );
        if (!rate.allowed) {
          results.push({ type: obligation.type, status: "FAILED", error: "rate_limited" });
          blockedReason = "rate_limited";
          break;
        }
        results.push({ type: obligation.type, status: "EXECUTED" });
        continue;
      }
      if (obligation.type === "ANCHOR_EVENT") {
        const payloadHash = hashCanonicalJson({
          event: obligation.event ?? "VERIFY",
          actionId: input.actionId,
          decision: input.decision,
          challengeHash: input.challengeHash,
          tokenHash: input.tokenHash,
          issuedAt: new Date().toISOString()
        });
        await insertAnchorOutbox(payloadHash, String(obligation.event ?? "VERIFY"), {
          action_id_hash: sha256Hex(input.actionId),
          decision: input.decision,
          event: obligation.event ?? "VERIFY"
        });
        results.push({ type: obligation.type, status: "EXECUTED" });
        continue;
      }
      if (obligation.type === "EMIT_EVENT") {
        await recordEmitEvent({
          eventType: String(obligation.event ?? "EVENT"),
          actionId: input.actionId,
          subjectDidHash: input.subjectDidHash,
          tokenHash: input.tokenHash,
          challengeHash: input.challengeHash
        });
        results.push({ type: obligation.type, status: "EXECUTED" });
        continue;
      }
      results.push({ type: obligation.type, status: "SKIPPED" });
    }
    await db("obligations_executions")
      .where({ id: finalExecutionId })
      .update({ status: "CONFIRMED", executed_at: now });
    return { executionId: finalExecutionId, obligations: results, blockedReason };
  } catch (error) {
    await db("obligations_executions")
      .where({ id: finalExecutionId })
      .update({
        status: "FAILED",
        error_code: error instanceof Error ? error.message.slice(0, 120) : "obligation_failed"
      });
    throw error;
  }
};
//# sourceMappingURL=execute.js.map
