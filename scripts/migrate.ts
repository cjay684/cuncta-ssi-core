import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createDb, runMigrations, closeDb } from "../packages/db/src/index.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");

dotenv.config({ path: path.join(repoRoot, ".env") });

const databaseUrl = process.env.MIGRATIONS_DATABASE_URL ?? process.env.DATABASE_URL;
if (!databaseUrl) {
  throw new Error("missing_required_envs:MIGRATIONS_DATABASE_URL|DATABASE_URL");
}
if (process.env.NODE_ENV === "production" && !process.env.MIGRATIONS_DATABASE_URL) {
  throw new Error("migrations_database_url_required_in_production");
}

const run = async () => {
  const db = createDb(databaseUrl);
  try {
    await runMigrations(db);
    console.log("migrations_complete");
  } finally {
    await closeDb(db);
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
