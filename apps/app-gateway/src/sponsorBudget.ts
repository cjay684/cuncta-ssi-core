import { type DbClient } from "@cuncta/db";
import { createHash, randomUUID } from "node:crypto";
import { getDb } from "./db.js";
import { config } from "./config.js";

type BudgetSnapshot = {
  day: string;
  didCreatesCount: number;
  issuesCount: number;
  anchorsCount: number;
  limits: {
    didCreatesPerDay: number;
    issuesPerDay: number;
  };
  killSwitch: boolean;
};

const getDayKey = () => new Date().toISOString().slice(0, 10);
const nowIso = () => new Date().toISOString();
const normalizeDayKey = (value: unknown) =>
  value instanceof Date ? value.toISOString().slice(0, 10) : String(value).slice(0, 10);
const hashRequestId = (requestId?: string) =>
  requestId ? createHash("sha256").update(requestId).digest("hex") : undefined;

const ensureRow = async (trx: DbClient, day: string) => {
  await trx("sponsor_budget_daily")
    .insert({
      day,
      did_creates_count: 0,
      issues_count: 0,
      anchors_count: 0,
      updated_at: new Date().toISOString()
    })
    .onConflict("day")
    .ignore();
};

const loadRow = async (trx: DbClient, day: string) => {
  return trx("sponsor_budget_daily").where({ day }).forUpdate().first();
};

const countReserved = async (trx: DbClient, day: string, kind: "did_create" | "issue") => {
  const row = await trx("sponsor_budget_events")
    .where({ day, kind, status: "RESERVED" })
    .count<{ count: string }>("id as count")
    .first();
  return Number(row?.count ?? 0);
};

type BudgetEventStatus = "RESERVED" | "COMMITTED" | "REVERTED";
type BudgetKind = "did_create" | "issue";

export type SponsorBudgetReservation = {
  id: string;
  day: string;
  kind: BudgetKind;
  status: BudgetEventStatus;
};

export const getSponsorBudgetSnapshot = async (): Promise<BudgetSnapshot> => {
  const day = getDayKey();
  const db = await getDb();
  await ensureRow(db, day);
  const row = await db("sponsor_budget_daily").where({ day }).first();
  return {
    day,
    didCreatesCount: Number(row?.did_creates_count ?? 0),
    issuesCount: Number(row?.issues_count ?? 0),
    anchorsCount: Number(row?.anchors_count ?? 0),
    limits: {
      didCreatesPerDay: config.SPONSOR_MAX_DID_CREATES_PER_DAY,
      issuesPerDay: config.SPONSOR_MAX_ISSUES_PER_DAY
    },
    killSwitch: config.SPONSOR_KILL_SWITCH
  };
};

export const reserveSponsorBudget = async (kind: BudgetKind, input?: { requestId?: string }) => {
  if (config.SPONSOR_KILL_SWITCH) {
    return { allowed: false, reason: "kill_switch" as const };
  }
  const day = getDayKey();
  const requestIdHash = hashRequestId(input?.requestId);
  const db = await getDb();
  return db.transaction(async (trx) => {
    await ensureRow(trx, day);
    if (requestIdHash) {
      const existing = await trx("sponsor_budget_events")
        .where({ day, kind, request_id_hash: requestIdHash })
        .forUpdate()
        .first();
      if (existing) {
        if (existing.status === "REVERTED") {
          await trx("sponsor_budget_events").where({ id: existing.id }).update({
            status: "RESERVED",
            updated_at: nowIso()
          });
          return {
            allowed: true as const,
            reservation: {
              id: existing.id as string,
              day,
              kind,
              status: "RESERVED" as const
            }
          };
        }
        return {
          allowed: true as const,
          reservation: {
            id: existing.id as string,
            day,
            kind,
            status: existing.status as BudgetEventStatus
          }
        };
      }
    }
    const row = await loadRow(trx, day);
    const didCreates = Number(row?.did_creates_count ?? 0);
    const issues = Number(row?.issues_count ?? 0);
    const reservedForKind = await countReserved(trx, day, kind);
    const nextDidCreates =
      kind === "did_create" ? didCreates + reservedForKind + 1 : didCreates + reservedForKind;
    const nextIssues = kind === "issue" ? issues + reservedForKind + 1 : issues + reservedForKind;
    if (kind === "did_create" && nextDidCreates > config.SPONSOR_MAX_DID_CREATES_PER_DAY) {
      return { allowed: false, reason: "budget_exceeded" as const };
    }
    if (kind === "issue" && nextIssues > config.SPONSOR_MAX_ISSUES_PER_DAY) {
      return { allowed: false, reason: "budget_exceeded" as const };
    }
    const eventId = randomUUID();
    await trx("sponsor_budget_events").insert({
      id: eventId,
      day,
      kind,
      status: "RESERVED",
      request_id_hash: requestIdHash ?? null,
      created_at: nowIso(),
      updated_at: nowIso()
    });
    return {
      allowed: true as const,
      reservation: {
        id: eventId,
        day,
        kind,
        status: "RESERVED" as const
      }
    };
  });
};

export const commitSponsorBudgetReservation = async (reservationId: string) => {
  const db = await getDb();
  return db.transaction(async (trx) => {
    const reservation = await trx("sponsor_budget_events")
      .where({ id: reservationId })
      .forUpdate()
      .first();
    if (!reservation) {
      return { committed: false as const, reason: "reservation_not_found" as const };
    }
    if (reservation.status === "COMMITTED") {
      return { committed: true as const, idempotent: true as const };
    }
    if (reservation.status !== "RESERVED") {
      return { committed: false as const, reason: "reservation_not_active" as const };
    }
    const day = normalizeDayKey(reservation.day);
    await ensureRow(trx, day);
    const row = await loadRow(trx, day);
    const didCreates = Number(row?.did_creates_count ?? 0);
    const issues = Number(row?.issues_count ?? 0);
    const kind = reservation.kind as BudgetKind;
    const nextDidCreates = kind === "did_create" ? didCreates + 1 : didCreates;
    const nextIssues = kind === "issue" ? issues + 1 : issues;
    if (nextDidCreates > config.SPONSOR_MAX_DID_CREATES_PER_DAY) {
      return { committed: false as const, reason: "budget_exceeded" as const };
    }
    if (nextIssues > config.SPONSOR_MAX_ISSUES_PER_DAY) {
      return { committed: false as const, reason: "budget_exceeded" as const };
    }
    await trx("sponsor_budget_daily").where({ day }).update({
      did_creates_count: nextDidCreates,
      issues_count: nextIssues,
      updated_at: nowIso()
    });
    await trx("sponsor_budget_events").where({ id: reservationId }).update({
      status: "COMMITTED",
      updated_at: nowIso()
    });
    return { committed: true as const, idempotent: false as const };
  });
};

export const revertSponsorBudgetReservation = async (reservationId: string) => {
  const db = await getDb();
  return db.transaction(async (trx) => {
    const reservation = await trx("sponsor_budget_events")
      .where({ id: reservationId })
      .forUpdate()
      .first();
    if (!reservation) {
      return { reverted: false as const, reason: "reservation_not_found" as const };
    }
    if (reservation.status === "REVERTED") {
      return { reverted: true as const, idempotent: true as const };
    }
    if (reservation.status === "COMMITTED") {
      return { reverted: false as const, reason: "reservation_committed" as const };
    }
    await trx("sponsor_budget_events").where({ id: reservationId }).update({
      status: "REVERTED",
      updated_at: nowIso()
    });
    return { reverted: true as const, idempotent: false as const };
  });
};
