import { getDb } from "./db.js";
import { DbClient } from "@cuncta/db";
import { hashCanonicalJson } from "@cuncta/shared";

const AUDIT_HEAD_KEY = "audit_log_head";
const AUDIT_HEAD_UPDATED_AT_KEY = "audit_log_head_updated_at";
const AUDIT_HEAD_ANCHORED_HASH_KEY = "audit_log_head_anchored_hash";
const AUDIT_HEAD_ANCHORED_AT_KEY = "audit_log_head_anchored_at";
const STARTUP_INTEGRITY_FAILURES_KEY = "startup_integrity_failures_total";
const PRIVACY_ERASE_EVER_KEY = "privacy_erase_ever";
const PRIVACY_ERASE_EPOCH_KEY = "privacy_erase_epoch";

const getMetaValue = async (trx: DbClient, key: string) => {
  const row = await trx("system_metadata").where({ key }).first();
  return row?.value ?? null;
};

export const writeAuditLog = async (
  eventType: string,
  data: Record<string, unknown>,
  trx?: DbClient
) => {
  const db = trx ?? (await getDb());
  return db.transaction(async (transaction) => {
    await transaction("system_metadata")
      .insert({ key: AUDIT_HEAD_KEY, value: "" })
      .onConflict("key")
      .ignore();

    const headRow = await transaction("system_metadata")
      .where({ key: AUDIT_HEAD_KEY })
      .forUpdate()
      .first();
    const prevHash = headRow?.value ?? "";
    const createdAt = new Date().toISOString();
    const dataHash = hashCanonicalJson(data);
    const chainHash = hashCanonicalJson({
      prevHash,
      dataHash,
      eventType,
      entityId: data.entityId ?? null,
      createdAt
    });

    await transaction("audit_logs").insert({
      event_type: eventType,
      entity_id: data.entityId ?? null,
      data_hash: dataHash,
      prev_hash: prevHash || null,
      chain_hash: chainHash,
      created_at: createdAt
    });

    await transaction("system_metadata")
      .insert({ key: AUDIT_HEAD_KEY, value: chainHash, updated_at: createdAt })
      .onConflict("key")
      .merge({ value: chainHash, updated_at: createdAt });

    await transaction("system_metadata")
      .insert({ key: AUDIT_HEAD_UPDATED_AT_KEY, value: createdAt, updated_at: createdAt })
      .onConflict("key")
      .merge({ value: createdAt, updated_at: createdAt });

    return { chainHash, dataHash, createdAt };
  });
};

export const getAuditHeadState = async () => {
  const db = await getDb();
  const [headRow, anchoredHashRow, anchoredAtRow] = await Promise.all([
    db("system_metadata").where({ key: AUDIT_HEAD_KEY }).first(),
    db("system_metadata").where({ key: AUDIT_HEAD_ANCHORED_HASH_KEY }).first(),
    db("system_metadata").where({ key: AUDIT_HEAD_ANCHORED_AT_KEY }).first()
  ]);
  return {
    headHash: headRow?.value ?? null,
    anchoredHash: anchoredHashRow?.value ?? null,
    anchoredAt: anchoredAtRow?.value ?? null
  };
};

export const markAuditHeadAnchored = async (headHash: string) => {
  const db = await getDb();
  const now = new Date().toISOString();
  await db("system_metadata")
    .insert({ key: AUDIT_HEAD_ANCHORED_HASH_KEY, value: headHash, updated_at: now })
    .onConflict("key")
    .merge({ value: headHash, updated_at: now });
  await db("system_metadata")
    .insert({ key: AUDIT_HEAD_ANCHORED_AT_KEY, value: now, updated_at: now })
    .onConflict("key")
    .merge({ value: now, updated_at: now });
};

export const incrementStartupIntegrityFailure = async (trx?: DbClient) => {
  const db = trx ?? (await getDb());
  return db.transaction(async (transaction) => {
    const current = await getMetaValue(transaction, STARTUP_INTEGRITY_FAILURES_KEY);
    const nextValue = String((current ? Number(current) : 0) + 1);
    const now = new Date().toISOString();
    await transaction("system_metadata")
      .insert({ key: STARTUP_INTEGRITY_FAILURES_KEY, value: nextValue, updated_at: now })
      .onConflict("key")
      .merge({ value: nextValue, updated_at: now });
  });
};

export const getStartupIntegrityFailureCount = async () => {
  const db = await getDb();
  const row = await db("system_metadata").where({ key: STARTUP_INTEGRITY_FAILURES_KEY }).first();
  return row ? Number(row.value) : 0;
};

export const markPrivacyEraseEver = async () => {
  const db = await getDb();
  const now = new Date().toISOString();
  await db("system_metadata")
    .insert({ key: PRIVACY_ERASE_EVER_KEY, value: "1", updated_at: now })
    .onConflict("key")
    .merge({ value: "1", updated_at: now });
};

export const getPrivacyEraseEver = async (trx?: DbClient) => {
  const db = trx ?? (await getDb());
  const row = await db("system_metadata").where({ key: PRIVACY_ERASE_EVER_KEY }).first();
  return row?.value === "1";
};

export const getPrivacyEraseEpoch = async (trx?: DbClient) => {
  const db = trx ?? (await getDb());
  const row = await db("system_metadata").where({ key: PRIVACY_ERASE_EPOCH_KEY }).first();
  return Number(row?.value ?? 0);
};

export const bumpPrivacyEraseEpoch = async () => {
  const db = await getDb();
  return db.transaction(async (trx) => {
    const current = await getPrivacyEraseEpoch(trx);
    const next = current + 1;
    const now = new Date().toISOString();
    await trx("system_metadata")
      .insert({ key: PRIVACY_ERASE_EPOCH_KEY, value: String(next), updated_at: now })
      .onConflict("key")
      .merge({ value: String(next), updated_at: now });
    return next;
  });
};
