import knex, { Knex } from "knex";
import path from "node:path";
import { fileURLToPath } from "node:url";

export type DbClient = Knex;

const migrationsDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "migrations"
);

export const createDb = (connectionString: string) =>
  knex({
    client: "pg",
    connection: connectionString,
    pool: { min: 0, max: 10 }
  });

export const runMigrations = async (db: DbClient) => {
  await db.migrate.latest({ directory: migrationsDir });
};

export const closeDb = async (db: DbClient) => {
  await db.destroy();
};
