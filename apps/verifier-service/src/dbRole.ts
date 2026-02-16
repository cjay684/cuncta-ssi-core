import { getDb } from "./db.js";
import { config } from "./config.js";

const quoteIdentifier = (value: string) => `"${value.replaceAll('"', '""')}"`;

const tableExists = async (tableName: string) => {
  const db = await getDb();
  const qualified = `public.${tableName}`;
  const existsResult = await db.raw("select to_regclass(?) as rel", [qualified]);
  return Boolean(existsResult?.rows?.[0]?.rel);
};

const probeReadAccess = async (tableName: string) => {
  if (!(await tableExists(tableName))) return false;
  const db = await getDb();
  const qualified = `${quoteIdentifier("public")}.${quoteIdentifier(tableName)}`;
  try {
    await db.raw(`select 1 from ${qualified} limit 1`);
    return true;
  } catch (error: any) {
    if (error?.code === "42501") {
      return false;
    }
    throw error;
  }
};

const hasWritePrivilege = async (tableName: string) => {
  if (!(await tableExists(tableName))) return false;
  const db = await getDb();
  const qualified = `${quoteIdentifier("public")}.${quoteIdentifier(tableName)}`;
  const rollbackSentinel = Symbol("strict_db_role_probe_rollback");
  try {
    await db.transaction(async (trx) => {
      await trx.raw(`delete from ${qualified} where false`);
      throw rollbackSentinel;
    });
  } catch (error: any) {
    if (error === rollbackSentinel) {
      return true;
    }
    if (error?.code === "42501") {
      return false;
    }
    throw error;
  }
  return false;
};

export const enforceStrictDbRole = async () => {
  if (!config.STRICT_DB_ROLE) return;
  const forbiddenWriteTables = [
    "issuer_keys",
    "status_lists",
    "status_list_versions",
    "issuance_events"
  ];
  for (const tableName of forbiddenWriteTables) {
    await probeReadAccess(tableName);
    if (await hasWritePrivilege(tableName)) {
      throw new Error(`strict_db_role_violation:${tableName}`);
    }
  }
};
