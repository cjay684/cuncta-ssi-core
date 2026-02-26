import { strict as assert } from "node:assert";
import { sha256Hex } from "../crypto/sha256.js";

process.env.NODE_ENV = "test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";
process.env.RETENTION_VERIFICATION_CHALLENGES_DAYS = "1";
process.env.RETENTION_RATE_LIMIT_EVENTS_DAYS = "1";
process.env.RETENTION_OBLIGATION_EVENTS_DAYS = "1";
process.env.RETENTION_AURA_SIGNALS_DAYS = "1";
process.env.RETENTION_AUDIT_LOGS_DAYS = "7";
process.env.ANCHOR_AUTH_SECRET =
  process.env.ANCHOR_AUTH_SECRET ?? "test-anchor-auth-secret-please-rotate";

const run = async () => {
  const { config } = await import("../config.js");
  config.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET;
  const { getDb } = await import("../db.js");
  const { runCleanupOnce } = await import("./cleanupWorker.js");
  const { getDidHashes } = await import("../pseudonymizer.js");

  const db = await getDb();
  await db("verification_challenges").del();
  await db("rate_limit_events").del();
  await db("obligation_events").del();
  await db("aura_signals").del();
  await db("audit_logs").del();

  const oldTimestamp = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();
  const recentTimestamp = new Date().toISOString();

  await db("verification_challenges").insert([
    {
      challenge_id: "challenge-old",
      challenge_hash: sha256Hex("nonce-old"),
      action_id: "marketplace.list_item",
      expires_at: oldTimestamp,
      consumed_at: oldTimestamp,
      created_at: oldTimestamp
    },
    {
      challenge_id: "challenge-recent",
      challenge_hash: sha256Hex("nonce-recent"),
      action_id: "marketplace.list_item",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      created_at: recentTimestamp
    }
  ]);

  await db("rate_limit_events").insert([
    {
      subject_hash: sha256Hex("subject-old"),
      action_id: "marketplace.list_item",
      created_at: oldTimestamp
    },
    {
      subject_hash: sha256Hex("subject-recent"),
      action_id: "marketplace.list_item",
      created_at: recentTimestamp
    }
  ]);

  await db("obligation_events").insert([
    {
      action_id: "marketplace.list_item",
      event_type: "VERIFY",
      subject_did_hash: getDidHashes("did:example:old").primary,
      token_hash: sha256Hex("token-old"),
      challenge_hash: sha256Hex("nonce-old"),
      event_hash: sha256Hex("event-old"),
      created_at: oldTimestamp
    },
    {
      action_id: "marketplace.list_item",
      event_type: "VERIFY",
      subject_did_hash: getDidHashes("did:example:recent").primary,
      token_hash: sha256Hex("token-recent"),
      challenge_hash: sha256Hex("nonce-recent"),
      event_hash: sha256Hex("event-recent"),
      created_at: recentTimestamp
    }
  ]);

  await db("aura_signals").insert([
    {
      subject_did_hash: getDidHashes("did:example:old").primary,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      event_hash: sha256Hex("signal-old"),
      created_at: oldTimestamp
    },
    {
      subject_did_hash: getDidHashes("did:example:recent").primary,
      domain: "marketplace",
      signal: "marketplace.listing_success",
      weight: 1,
      event_hash: sha256Hex("signal-recent"),
      created_at: recentTimestamp
    }
  ]);

  await db("audit_logs").insert([
    {
      event_type: "TEST_OLD",
      entity_id: "entity-old",
      data_hash: sha256Hex("audit-old"),
      created_at: oldTimestamp
    },
    {
      event_type: "TEST_RECENT",
      entity_id: "entity-recent",
      data_hash: sha256Hex("audit-recent"),
      created_at: recentTimestamp
    }
  ]);

  await runCleanupOnce();

  const challengeCount = await db("verification_challenges")
    .count<{ count: string }>("challenge_id as count")
    .first();
  assert.equal(Number(challengeCount?.count ?? 0), 1);

  const rateLimitCount = await db("rate_limit_events")
    .count<{ count: string }>("id as count")
    .first();
  assert.equal(Number(rateLimitCount?.count ?? 0), 1);

  const obligationCount = await db("obligation_events")
    .count<{ count: string }>("id as count")
    .first();
  assert.equal(Number(obligationCount?.count ?? 0), 1);

  const auraCount = await db("aura_signals").count<{ count: string }>("id as count").first();
  assert.equal(Number(auraCount?.count ?? 0), 1);

  const auditCount = await db("audit_logs").count<{ count: string }>("id as count").first();
  assert.equal(Number(auditCount?.count ?? 0), 1);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
