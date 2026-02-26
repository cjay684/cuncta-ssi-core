import { createDb, runMigrations, DbClient } from "@cuncta/db";
import { config } from "./config.js";
import { ensureBaselinePolicies } from "./bootstrap.js";

let db: DbClient | null = null;
let ready: Promise<DbClient> | null = null;
let bootstrapped = false;

export const getDb = async () => {
  if (db) {
    return db;
  }
  if (!ready) {
    ready = (async () => {
      const client = createDb(config.DATABASE_URL);
      if (config.AUTO_MIGRATE) {
        await runMigrations(client);
      }
      // Idempotent baseline policy bootstrap (safe even if migrations already ran).
      await ensureBaselinePolicies(client);
      bootstrapped = true;
      db = client;
      return client;
    })();
  }
  return ready;
};

export const isDbReady = () => Boolean(db) && bootstrapped;
