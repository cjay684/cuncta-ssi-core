import { createDb, type DbClient } from "@cuncta/db";
import { config } from "./config.js";

let db: DbClient | null = null;

export const getDb = async (): Promise<DbClient> => {
  if (!db) {
    db = createDb(config.DATABASE_URL);
  }
  return db;
};
