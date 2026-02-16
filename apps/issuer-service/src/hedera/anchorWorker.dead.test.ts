import { strict as assert } from "node:assert";

process.env.NODE_ENV = "test";
process.env.ANCHOR_MAX_ATTEMPTS = "2";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

const run = async () => {
  const { getDb } = await import("../db.js");
  const { config } = await import("../config.js");
  const { processAnchorOutboxOnce } = await import("./anchorWorker.js");
  config.ANCHOR_MAX_ATTEMPTS = 2;

  const db = await getDb();
  await db("anchor_receipts").del();
  await db("anchor_outbox").del();

  await db("anchor_outbox").insert({
    outbox_id: "outbox-dead-1",
    event_type: "VERIFY",
    payload_hash: "hash_test_dead",
    payload_meta: {},
    status: "PENDING",
    attempts: 1,
    next_retry_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  const publisher = async () => {
    throw new Error("forced_failure");
  };

  await processAnchorOutboxOnce(publisher);

  const outbox = await db("anchor_outbox").where({ outbox_id: "outbox-dead-1" }).first();
  assert.equal(outbox?.status, "DEAD");
  assert.equal(Number(outbox?.attempts ?? 0), 2);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
