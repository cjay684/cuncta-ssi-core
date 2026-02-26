import { getDb } from "./db.js";
import { DbClient } from "@cuncta/db";
import { hashCanonicalJson } from "@cuncta/shared";

const AUDIT_HEAD_KEY = "audit_log_head";
const AUDIT_HEAD_UPDATED_AT_KEY = "audit_log_head_updated_at";

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
