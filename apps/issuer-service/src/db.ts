import { createDb, runMigrations, DbClient } from "@cuncta/db";
import { config } from "./config.js";

let db: DbClient | null = null;
let ready: Promise<DbClient> | null = null;

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
      db = client;
      return client;
    })();
  }
  return ready;
};
