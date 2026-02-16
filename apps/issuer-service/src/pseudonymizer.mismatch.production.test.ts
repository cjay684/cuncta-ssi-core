import { strict as assert } from "node:assert";

process.env.NODE_ENV = "production";
process.env.PSEUDONYMIZER_PEPPER = "pepper-a";
process.env.PSEUDONYMIZER_ALLOW_LEGACY = "false";
process.env.ISSUER_BASE_URL = "http://issuer.test";
process.env.DATABASE_URL =
  process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

const run = async () => {
  const { ensurePseudonymizerConsistency } = await import("./pseudonymizer.js");
  const { getDb } = await import("./db.js");
  const db = await getDb();
  await db("system_metadata").del();

  await ensurePseudonymizerConsistency();

  await db("system_metadata")
    .where({ key: "pseudonymizer_fingerprint" })
    .update({ value: "mismatch", updated_at: new Date().toISOString() });

  let threw = false;
  try {
    await ensurePseudonymizerConsistency();
  } catch (error) {
    threw = true;
    const message = error instanceof Error ? error.message : String(error);
    assert.equal(message, "pseudonymizer_mismatch");
  }
  assert.equal(threw, true);
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
