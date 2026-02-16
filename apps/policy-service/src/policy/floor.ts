import { getDb } from "../db.js";
import { config } from "../config.js";

const nowIso = () => new Date().toISOString();

export const ensurePolicyVersionFloors = async () => {
  if (!config.POLICY_VERSION_FLOOR_ENFORCED) return;
  const db = await getDb();
  const latestRows = (await db("policies")
    .select("action_id")
    .max("version as max_version")
    .where({ enabled: true })
    .groupBy("action_id")) as Array<{ action_id: string; max_version: number }>;
  for (const row of latestRows) {
    const actionId = row.action_id;
    const maxVersion = Number(row.max_version ?? 0);
    if (!actionId || maxVersion < 1) continue;
    const existing = await db("policy_version_floor").where({ action_id: actionId }).first();
    if (!existing) {
      await db("policy_version_floor").insert({
        action_id: actionId,
        min_version: maxVersion,
        updated_at: nowIso()
      });
    }
  }
};

export const getPolicyVersionFloor = async (actionId: string) => {
  const db = await getDb();
  const row = await db("policy_version_floor").where({ action_id: actionId }).first();
  return Number(row?.min_version ?? 0);
};

export const setPolicyVersionFloor = async (actionId: string, minVersion: number) => {
  const db = await getDb();
  await db("policy_version_floor")
    .insert({
      action_id: actionId,
      min_version: minVersion,
      updated_at: nowIso()
    })
    .onConflict("action_id")
    .merge({
      min_version: minVersion,
      updated_at: nowIso()
    });
};
