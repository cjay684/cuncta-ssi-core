import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.RETENTION_AURA_SIGNALS_DAYS = "1";
process.env.RETENTION_AURA_STATE_DAYS = "1";
process.env.RETENTION_AURA_ISSUANCE_QUEUE_DAYS = "1";
process.env.RETENTION_VERIFICATION_CHALLENGES_DAYS =
  process.env.RETENTION_VERIFICATION_CHALLENGES_DAYS ?? "1";
process.env.RETENTION_RATE_LIMIT_EVENTS_DAYS = process.env.RETENTION_RATE_LIMIT_EVENTS_DAYS ?? "1";
process.env.RETENTION_OBLIGATION_EVENTS_DAYS = process.env.RETENTION_OBLIGATION_EVENTS_DAYS ?? "1";
process.env.RETENTION_AUDIT_LOGS_DAYS = process.env.RETENTION_AUDIT_LOGS_DAYS ?? "1";
process.env.ANCHOR_AUTH_SECRET =
  process.env.ANCHOR_AUTH_SECRET ?? "test-anchor-auth-secret-please-rotate";

test("cleanup worker applies Aura retention (signals/state/terminal queue rows)", async () => {
  const { getDb } = await import("../db.js");
  const { runCleanupOnce } = await import("./cleanupWorker.js");

  const db = await getDb();
  const subject = "subhash_" + randomUUID();
  const old = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
  const recent = new Date().toISOString();

  await db("aura_signals").where({ subject_did_hash: subject }).del();
  await db("aura_state").where({ subject_did_hash: subject }).del();
  await db("aura_issuance_queue").where({ subject_did_hash: subject }).del();

  await db("aura_signals").insert([
    {
      subject_did_hash: subject,
      domain: "social",
      signal: "social.post.create",
      weight: 1,
      event_hash: "evt_old",
      created_at: old,
      processed_at: old
    },
    {
      subject_did_hash: subject,
      domain: "social",
      signal: "social.post.create",
      weight: 1,
      event_hash: "evt_recent",
      created_at: recent,
      processed_at: recent
    }
  ]);

  await db("aura_state").insert([
    {
      subject_did_hash: subject,
      domain: "social",
      state: { tier: "silver", score: 10, diversity: 2, window_days: 30, last_signal_at: old },
      updated_at: old
    },
    {
      subject_did_hash: subject,
      domain: "marketplace",
      state: { tier: "silver", score: 10, diversity: 2, window_days: 30, last_signal_at: recent },
      updated_at: recent
    }
  ]);

  await db("aura_issuance_queue").insert([
    {
      queue_id: `aq_${randomUUID()}`,
      rule_id: "rule_old",
      subject_did_hash: subject,
      domain: "social",
      output_vct: "cuncta.test.cap",
      reason_hash: "rh_old",
      status: "ISSUED",
      issued_at: old,
      created_at: old,
      updated_at: old
    },
    {
      queue_id: `aq_${randomUUID()}`,
      rule_id: "rule_recent",
      subject_did_hash: subject,
      domain: "social",
      output_vct: "cuncta.test.cap",
      reason_hash: "rh_recent",
      status: "PENDING",
      issued_at: null,
      created_at: recent,
      updated_at: recent
    }
  ]);

  await runCleanupOnce();

  const remainingSignals = await db("aura_signals")
    .where({ subject_did_hash: subject })
    .select("event_hash");
  assert.equal(
    remainingSignals.some((r: { event_hash: string }) => r.event_hash === "evt_old"),
    false
  );
  assert.equal(
    remainingSignals.some((r: { event_hash: string }) => r.event_hash === "evt_recent"),
    true
  );

  const remainingState = await db("aura_state")
    .where({ subject_did_hash: subject })
    .select("domain");
  assert.equal(
    remainingState.some((r: { domain: string }) => r.domain === "social"),
    false
  );
  assert.equal(
    remainingState.some((r: { domain: string }) => r.domain === "marketplace"),
    true
  );

  const remainingQueue = await db("aura_issuance_queue")
    .where({ subject_did_hash: subject })
    .select("status");
  assert.equal(
    remainingQueue.some((r: { status: string }) => r.status === "ISSUED"),
    false
  );
  assert.equal(
    remainingQueue.some((r: { status: string }) => r.status === "PENDING"),
    true
  );
});
