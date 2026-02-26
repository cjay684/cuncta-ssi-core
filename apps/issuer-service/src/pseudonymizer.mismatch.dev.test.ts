import { strict as assert } from "node:assert";

process.env.NODE_ENV = "development";
process.env.PSEUDONYMIZER_PEPPER = "pepper-a";
process.env.PSEUDONYMIZER_ALLOW_LEGACY = "true";
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

  const warnings: string[] = [];
  const originalWarn = console.warn;
  console.warn = (message?: unknown) => {
    warnings.push(String(message ?? ""));
  };

  await ensurePseudonymizerConsistency();

  console.warn = originalWarn;
  assert.ok(
    warnings.some((entry) => entry.includes("pseudonymizer.mismatch")),
    "expected mismatch warning in dev"
  );
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
