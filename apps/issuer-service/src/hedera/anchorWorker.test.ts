import { strict as assert } from "node:assert";

process.env.NODE_ENV = "test";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

const run = async () => {
  const { getDb } = await import("../db.js");
  const { processAnchorOutboxOnce } = await import("./anchorWorker.js");

  const db = await getDb();
  await db("anchor_receipts").del();
  await db("anchor_outbox").del();

  const payloadHash = "hash_test_anchor";
  await db("anchor_outbox").insert({
    outbox_id: "outbox-1",
    event_type: "VERIFY",
    payload_hash: payloadHash,
    payload_meta: {},
    status: "PENDING",
    attempts: 0,
    next_retry_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const staleHash = "hash_test_stale";
  await db("anchor_outbox").insert({
    outbox_id: "outbox-2",
    event_type: "OBLIGATION_EXECUTED",
    payload_hash: staleHash,
    payload_meta: {},
    status: "PROCESSING",
    attempts: 0,
    next_retry_at: new Date().toISOString(),
    processing_started_at: new Date(Date.now() - 5 * 60_000).toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const publisher = async () => ({
    topicId: "0.0.1",
    sequenceNumber: "1",
    consensusTimestamp: "123456.000000000"
  });

  await Promise.all([processAnchorOutboxOnce(publisher), processAnchorOutboxOnce(publisher)]);

  const receiptCount = await db("anchor_receipts")
    .where({ payload_hash: payloadHash })
    .count<{ count: string }>("payload_hash as count")
    .first();
  assert.equal(Number(receiptCount?.count ?? 0), 1);

  const staleReceipt = await db("anchor_receipts")
    .where({ payload_hash: staleHash })
    .count<{ count: string }>("payload_hash as count")
    .first();
  assert.equal(Number(staleReceipt?.count ?? 0), 1);

  const outbox = await db("anchor_outbox").where({ outbox_id: "outbox-1" }).first();
  assert.equal(outbox?.status, "CONFIRMED");
  const staleOutbox = await db("anchor_outbox").where({ outbox_id: "outbox-2" }).first();
  assert.equal(staleOutbox?.status, "CONFIRMED");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
