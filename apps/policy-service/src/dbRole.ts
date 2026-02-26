import { getDb } from "./db.js";
import { config } from "./config.js";

const quoteIdentifier = (value: string) => `"${value.replaceAll('"', '""')}"`;

const getPgErrorCode = (error: unknown): string | undefined => {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  const maybeCode = (error as { code?: unknown }).code;
  return typeof maybeCode === "string" ? maybeCode : undefined;
};

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
  } catch (error: unknown) {
    if (getPgErrorCode(error) === "42501") {
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
  } catch (error: unknown) {
    if (error === rollbackSentinel) {
      return true;
    }
    if (getPgErrorCode(error) === "42501") {
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
