import { FastifyInstance, FastifyReply } from "fastify";
import { randomBytes, randomUUID } from "node:crypto";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { z } from "zod";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { log } from "../log.js";
import { sha256Hex } from "../crypto/sha256.js";
import { hashCanonicalJson, makeErrorResponse } from "@cuncta/shared";
import { getDidHashes, getLookupHashes } from "../pseudonymizer.js";
import { metrics } from "../metrics.js";
import { bumpPrivacyEraseEpoch, markPrivacyEraseEver } from "../audit.js";
import { requireServiceAuth } from "../auth.js";

const requestSchema = z.object({
  did: z.string().min(3)
});

const confirmSchema = z.object({
  requestId: z.string().min(10),
  nonce: z.string().min(10),
  kbJwt: z.string().min(10)
});

const restrictSchema = z.object({
  reason: z.string().min(1).max(500).optional()
});

const eraseSchema = z.object({
  mode: z.literal("unlink")
});

const internalPrivacyStatusSchema = z.object({
  subjectDidHash: z.string().min(10)
});

const exportResponseSchema = z.object({
  subject: z.object({ did_hash: z.string() }),
  generated_at: z.string(),
  issuance: z.array(z.record(z.string(), z.unknown())),
  telemetry: z.record(z.string(), z.unknown()),
  anchors: z.record(z.string(), z.unknown()),
  nextToken: z.string().min(10).optional()
});

const getBearer = (authorization?: string) => {
  if (!authorization) return "";
  if (!authorization.startsWith("Bearer ")) return "";
  return authorization.slice(7);
};

const getDsrContext = async (
  request: { headers: { authorization?: string } },
  reply: FastifyReply
) => {
  const token = getBearer(request.headers.authorization);
  if (!token) {
    reply.code(401).send(makeErrorResponse("invalid_request", "Missing DSR token"));
    return null;
  }
  const tokenHash = sha256Hex(token);
  const db = await getDb();
  const now = new Date().toISOString();
  const row = await db("privacy_tokens")
    .where({ token_hash: tokenHash })
    .andWhere("expires_at", ">", now)
    .first();
  if (!row) {
    reply.code(401).send(makeErrorResponse("invalid_request", "Invalid DSR token"));
    return null;
  }
  return {
    didHash: row.did_hash as string,
    legacyHash: (row.did_hash_legacy as string | null | undefined) ?? null,
    tokenHash
  };
};

const rotateDsrToken = async (input: {
  didHash: string;
  legacyHash?: string | null;
  tokenHash: string;
}) => {
  const db = await getDb();
  const nextToken = randomBytes(32).toString("base64url");
  const nextHash = sha256Hex(nextToken);
  const expiresAt = new Date(Date.now() + config.PRIVACY_TOKEN_TTL_SECONDS * 1000).toISOString();
  await db.transaction(async (trx) => {
    await trx("privacy_tokens").where({ token_hash: input.tokenHash }).del();
    await trx("privacy_tokens").insert({
      token_hash: nextHash,
      did_hash: input.didHash,
      did_hash_legacy: input.legacyHash ?? null,
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    });
  });
  return { nextToken, expiresAt };
};

const verifyKbJwt = async (input: { kbJwt: string; nonce: string; audience: string }) => {
  const kbHeader = decodeProtectedHeader(input.kbJwt);
  const kbDecoded = decodeJwt(input.kbJwt) as Record<string, unknown>;
  const cnf = kbDecoded.cnf as { jwk?: Record<string, unknown> } | undefined;
  if (!cnf?.jwk) {
    throw new Error("kb_jwt_missing_cnf");
  }
  const holderKey = await importJWK(cnf.jwk as never, kbHeader.alg);
  const verified = await jwtVerify(input.kbJwt, holderKey).catch(() => null);
  if (!verified) {
    throw new Error("binding_invalid");
  }
  if (typeof verified.payload.exp !== "number") {
    throw new Error("kb_jwt_missing_exp");
  }
  if (verified.payload.aud !== input.audience) {
    throw new Error("aud_mismatch");
  }
  if (verified.payload.nonce !== input.nonce) {
    throw new Error("nonce_mismatch");
  }
};

const tableExistsCache = new Map<string, boolean>();

const hasTable = async (tableName: string) => {
  if (tableExistsCache.has(tableName)) {
    return tableExistsCache.get(tableName) ?? false;
  }
  const exists = await (await getDb()).schema.hasTable(tableName);
  tableExistsCache.set(tableName, exists);
  return exists;
};

type SubjectLinkColumn = {
  table: string;
  column: string;
  hasDeletedAt: boolean;
};

let subjectLinkInventory: {
  loadedAt: number;
  truncated: boolean;
  columns: SubjectLinkColumn[];
} | null = null;

const loadSubjectLinkInventory = async (): Promise<{
  truncated: boolean;
  columns: SubjectLinkColumn[];
}> => {
  const now = Date.now();
  if (subjectLinkInventory && now - subjectLinkInventory.loadedAt < 5 * 60_000) {
    return { truncated: subjectLinkInventory.truncated, columns: subjectLinkInventory.columns };
  }
  const db = await getDb();

  // Conservative inventory: any column that can carry a DID hash or subject hash.
  // This favors false-positives (reporting "not complete") over false completion.
  const rawColumns = (await db
    .select("table_name", "column_name")
    .from("information_schema.columns")
    .where({ table_schema: "public" })
    .andWhere((builder) =>
      builder
        .whereILike("column_name", "%did_hash%")
        .orWhereILike("column_name", "%subject_hash%")
        .orWhereILike("column_name", "%subject_did_hash%")
    )) as Array<{ table_name: string; column_name: string }>;

  const deletedAtTables = new Set<string>(
    (
      (await db
        .select("table_name")
        .from("information_schema.columns")
        .where({ table_schema: "public", column_name: "deleted_at" })) as Array<{
        table_name: string;
      }>
    ).map((row) => row.table_name)
  );

  const excludedTables = new Set<string>([
    "knex_migrations",
    "knex_migrations_lock",
    // Tombstones intentionally persist by design; don't count them as "residual linkage".
    "privacy_tombstones"
  ]);

  const MAX_COLUMNS = 5000;
  const columns: SubjectLinkColumn[] = [];
  let truncated = false;
  for (const entry of rawColumns) {
    if (excludedTables.has(entry.table_name)) continue;
    columns.push({
      table: entry.table_name,
      column: entry.column_name,
      hasDeletedAt: deletedAtTables.has(entry.table_name)
    });
    if (columns.length >= MAX_COLUMNS) {
      truncated = true;
      break;
    }
  }

  subjectLinkInventory = { loadedAt: now, truncated, columns };
  return { truncated, columns };
};

const countLinkedRows = async (input: {
  table: string;
  column: string;
  lookup: string[];
  deletedAtColumn?: string;
  activeStatusColumn?: string;
  activeStatusValue?: string;
}) => {
  if (!(await hasTable(input.table))) return 0;
  const db = await getDb();
  let query = db(input.table).whereIn(input.column, input.lookup);
  if (input.deletedAtColumn) {
    query = query.whereNull(input.deletedAtColumn);
  }
  if (input.activeStatusColumn && input.activeStatusValue) {
    query = query.where(input.activeStatusColumn, input.activeStatusValue);
  }
  const row = await query.count<{ count: string }>("* as count").first();
  return Number(row?.count ?? 0);
};

const getEraseCompletionState = async (didHash: string, legacyHash: string | null) => {
  const db = await getDb();
  const lookup = getLookupHashes({ primary: didHash, legacy: legacyHash });
  const latestTombstone = await db("privacy_tombstones")
    .whereIn("did_hash", lookup)
    .orderBy("erased_at", "desc")
    .first();

  const pendingTableCounts: Record<string, number> = {};
  let linkedResidualCount = 0;
  let linkedActiveResidualCount = 0;
  let inventoryTruncated = false;
  try {
    const inventory = await loadSubjectLinkInventory();
    inventoryTruncated = inventory.truncated;
    for (const entry of inventory.columns) {
      const key = `${entry.table}.${entry.column}`;
      const total = await countLinkedRows({ table: entry.table, column: entry.column, lookup });
      pendingTableCounts[key] = total;
      linkedResidualCount += total;
      if (entry.hasDeletedAt) {
        const active = await countLinkedRows({
          table: entry.table,
          column: entry.column,
          lookup,
          deletedAtColumn: "deleted_at"
        });
        pendingTableCounts[`${key}.active`] = active;
        linkedActiveResidualCount += active;
      } else {
        linkedActiveResidualCount += total;
      }
    }
  } catch (error) {
    // Conservative: if we cannot compute inventory, never claim completion.
    pendingTableCounts["inventory_error"] = 1;
    linkedResidualCount = Number.POSITIVE_INFINITY;
    linkedActiveResidualCount = Number.POSITIVE_INFINITY;
    inventoryTruncated = true;
    log.warn("privacy.erase.inventory_failed", {
      error: error instanceof Error ? error.message : "unknown_error"
    });
  }

  const purgePendingCount = 0;
  const purgeDeadLetteredCount = 0;

  const offchainUnlinkDone = linkedResidualCount === 0 && !inventoryTruncated;
  return {
    requestedAt: typeof latestTombstone?.erased_at === "string" ? latestTombstone.erased_at : null,
    offchainUnlinkDone,
    purgePending: purgePendingCount > 0,
    purgePendingCount,
    purgeDeadLetteredCount,
    linkedResidualCount,
    linkedActiveResidualCount,
    inventoryTruncated,
    pendingTableCounts
  };
};

export const registerPrivacyRoutes = (app: FastifyInstance) => {
  app.get("/v1/admin/privacy/status", async (request, reply) => {
    await requireServiceAuth(request, reply, { requireAdminScope: ["issuer:privacy_status"] });
    if (reply.sent) return;
    const query = internalPrivacyStatusSchema.parse(request.query ?? {});
    const db = await getDb();
    const [restriction, tombstone] = await Promise.all([
      db("privacy_restrictions").where({ did_hash: query.subjectDidHash }).first(),
      db("privacy_tombstones").where({ did_hash: query.subjectDidHash }).first()
    ]);
    return reply.send({
      restricted: Boolean(restriction),
      tombstoned: Boolean(tombstone)
    });
  });

  app.post("/v1/privacy/request", async (request, reply) => {
    const body = requestSchema.parse(request.body);
    const db = await getDb();
    const requestId = randomUUID();
    const nonce = randomBytes(32).toString("base64url");
    const { primary, legacy } = getDidHashes(body.did);
    const didHash = primary;
    const expiresAt = new Date(
      Date.now() + config.PRIVACY_CHALLENGE_TTL_SECONDS * 1000
    ).toISOString();
    const audience = "cuncta.privacy:request";
    await db("privacy_requests")
      .insert({
        request_id: requestId,
        did_hash: didHash,
        did_hash_legacy: legacy ?? null,
        nonce_hash: sha256Hex(nonce),
        audience,
        expires_at: expiresAt,
        created_at: new Date().toISOString()
      })
      .onConflict("request_id")
      .ignore();
    log.info("privacy.request", { requestId, didHash });
    metrics.incCounter("privacy_request_total");
    return reply.send({
      requestId,
      nonce,
      audience,
      expires_at: expiresAt
    });
  });

  app.post("/v1/privacy/confirm", async (request, reply) => {
    const body = confirmSchema.parse(request.body);
    const db = await getDb();
    const row = await db("privacy_requests").where({ request_id: body.requestId }).first();
    if (!row) {
      return reply.code(404).send(
        makeErrorResponse("invalid_request", "Privacy request not found", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (row.consumed_at) {
      return reply.code(409).send(
        makeErrorResponse("invalid_request", "Privacy request already used", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (row.expires_at && new Date(row.expires_at as string) <= new Date()) {
      return reply.code(410).send(
        makeErrorResponse("invalid_request", "Privacy request expired", {
          devMode: config.DEV_MODE
        })
      );
    }
    if (sha256Hex(body.nonce) !== row.nonce_hash) {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Invalid nonce", {
          devMode: config.DEV_MODE
        })
      );
    }
    try {
      await verifyKbJwt({
        kbJwt: body.kbJwt,
        nonce: body.nonce,
        audience: row.audience as string
      });
    } catch (error) {
      return reply.code(401).send(
        makeErrorResponse("invalid_request", "KB-JWT invalid", {
          details: error instanceof Error ? error.message : "invalid_kb_jwt",
          devMode: config.DEV_MODE
        })
      );
    }

    const consumedAt = new Date().toISOString();
    await db("privacy_requests")
      .where({ request_id: body.requestId })
      .update({ consumed_at: consumedAt });
    const dsrToken = randomBytes(32).toString("base64url");
    const tokenHash = sha256Hex(dsrToken);
    const expiresAt = new Date(Date.now() + config.PRIVACY_TOKEN_TTL_SECONDS * 1000).toISOString();
    await db("privacy_tokens").insert({
      token_hash: tokenHash,
      did_hash: row.did_hash,
      did_hash_legacy: row.did_hash_legacy ?? null,
      expires_at: expiresAt,
      created_at: new Date().toISOString()
    });
    log.info("privacy.confirm", { requestId: body.requestId, didHash: row.did_hash });
    return reply.send({ dsrToken, expires_at: expiresAt });
  });

  app.get("/v1/privacy/export", async (request, reply) => {
    const context = await getDsrContext(request, reply);
    if (!context) return;
    const db = await getDb();
    const didHash = context.didHash;
    const lookupHashes = getLookupHashes({ primary: didHash, legacy: context.legacyHash });

    const issuance = await db("issuance_events")
      .whereIn("subject_did_hash", lookupHashes)
      .select("vct", "status_list_id", "status_index", "issued_at", "credential_fingerprint");

    const statusListIds = Array.from(new Set(issuance.map((row) => row.status_list_id))).filter(
      (id) => typeof id === "string"
    );
    const statusLists = statusListIds.length
      ? await db("status_lists")
          .whereIn("status_list_id", statusListIds)
          .select("status_list_id", "purpose", "bitstring_size", "current_version", "updated_at")
      : [];

    const [
      obligationEventsCount,
      obligationEventsMax,
      obligationExecutionsCount,
      obligationExecutionsMax,
      rateLimitsCount,
      rateLimitsMax
    ] = await Promise.all([
      db("obligation_events")
        .whereIn("subject_did_hash", lookupHashes)
        .count<{ count: string }>("id as count")
        .first(),
      db("obligation_events")
        .whereIn("subject_did_hash", lookupHashes)
        .max<{ max: string }>("created_at as max")
        .first(),
      db("obligations_executions")
        .whereIn("subject_did_hash", lookupHashes)
        .count<{ count: string }>("id as count")
        .first(),
      db("obligations_executions")
        .whereIn("subject_did_hash", lookupHashes)
        .max<{ max: string }>("executed_at as max")
        .first(),
      db("rate_limit_events")
        .whereIn("subject_hash", lookupHashes)
        .count<{ count: string }>("id as count")
        .first(),
      db("rate_limit_events")
        .whereIn("subject_hash", lookupHashes)
        .max<{ max: string }>("created_at as max")
        .first()
    ]);

    const outboxQuery = db("anchor_outbox").select(
      "payload_hash",
      "event_type",
      "status",
      "created_at"
    );
    if (lookupHashes.length > 1) {
      outboxQuery.whereRaw("payload_meta->>'subject_did_hash' in (?, ?)", lookupHashes);
    } else {
      outboxQuery.whereRaw("payload_meta->>'subject_did_hash' = ?", [didHash]);
    }
    const outboxRows = await outboxQuery;
    const outboxHashes = outboxRows.map((row) => row.payload_hash as string);
    const receipts = outboxHashes.length
      ? await db("anchor_receipts")
          .whereIn("payload_hash", outboxHashes)
          .select(
            "payload_hash",
            "topic_id",
            "sequence_number",
            "consensus_timestamp",
            "created_at"
          )
      : [];

    const payload = {
      subject: { did_hash: didHash },
      generated_at: new Date().toISOString(),
      issuance,
      telemetry: {
        obligation_events: {
          count: Number(obligationEventsCount?.count ?? 0),
          last_created_at: obligationEventsMax?.max ?? null
        },
        obligations_executions: {
          count: Number(obligationExecutionsCount?.count ?? 0),
          last_executed_at: obligationExecutionsMax?.max ?? null
        },
        rate_limit_events: {
          count: Number(rateLimitsCount?.count ?? 0),
          last_created_at: rateLimitsMax?.max ?? null
        }
      },
      anchors: {
        outbox: outboxRows,
        receipts,
        status_lists: statusLists
      }
    };

    const { nextToken } = await rotateDsrToken({
      didHash: context.didHash,
      legacyHash: context.legacyHash,
      tokenHash: context.tokenHash
    });
    (payload as { nextToken?: string }).nextToken = nextToken;
    exportResponseSchema.parse(payload);
    return reply.send(payload);
  });

  app.post("/v1/privacy/restrict", async (request, reply) => {
    const context = await getDsrContext(request, reply);
    if (!context) return;
    const body = restrictSchema.parse(request.body ?? {});
    const db = await getDb();
    const reasonHash =
      body.reason && body.reason.trim().length > 0
        ? hashCanonicalJson({ reason: body.reason.trim() })
        : null;
    const lookup = getLookupHashes({ primary: context.didHash, legacy: context.legacyHash });
    const restrictedAt = new Date().toISOString();
    for (const didHash of lookup) {
      await db("privacy_restrictions")
        .insert({
          did_hash: didHash,
          restricted_at: restrictedAt,
          reason_hash: reasonHash
        })
        .onConflict("did_hash")
        .merge({
          restricted_at: restrictedAt,
          reason_hash: reasonHash
        });
    }
    log.info("privacy.restrict", { didHash: context.didHash });
    const { nextToken } = await rotateDsrToken({
      didHash: context.didHash,
      legacyHash: context.legacyHash,
      tokenHash: context.tokenHash
    });
    return reply.send({ status: "restricted", nextToken });
  });

  app.post("/v1/privacy/erase", async (request, reply) => {
    const context = await getDsrContext(request, reply);
    if (!context) return;
    const body = eraseSchema.parse(request.body ?? {});
    if (body.mode !== "unlink") {
      return reply.code(400).send(
        makeErrorResponse("invalid_request", "Unsupported erase mode", {
          devMode: config.DEV_MODE
        })
      );
    }
    const db = await getDb();
    const didHash = context.didHash;
    const lookup = getLookupHashes({ primary: didHash, legacy: context.legacyHash });

    await db.transaction(async (trx) => {
      await trx("obligation_events").whereIn("subject_did_hash", lookup).del();
      await trx("obligations_executions").whereIn("subject_did_hash", lookup).del();
      await trx("rate_limit_events").whereIn("subject_hash", lookup).del();
      await trx("privacy_requests").whereIn("did_hash", lookup).del();
      await trx("privacy_tokens").whereIn("did_hash", lookup).del();
      await trx("privacy_restrictions").whereIn("did_hash", lookup).del();
      // Legacy (Semaphore-era) table; safe to delete rows if present.
      await trx("zk_age_group_members").whereIn("subject_did_hash", lookup).del();
      await trx("issuance_events")
        .whereIn("subject_did_hash", lookup)
        .update({ subject_did_hash: null });
      const erasedAt = new Date().toISOString();
      for (const hash of lookup) {
        await trx("privacy_tombstones")
          .insert({ did_hash: hash, erased_at: erasedAt })
          .onConflict("did_hash")
          .merge({ erased_at: erasedAt });
      }
    });

    // If legacy ZK group tables exist, they are treated as best-effort cleanup only.

    log.info("privacy.erase", { didHash });
    metrics.incCounter("privacy_erase_total");
    await markPrivacyEraseEver();
    await bumpPrivacyEraseEpoch();
    const { nextToken } = await rotateDsrToken({
      didHash: context.didHash,
      legacyHash: context.legacyHash,
      tokenHash: context.tokenHash
    });
    const completion = await getEraseCompletionState(context.didHash, context.legacyHash);
    return reply.send({
      status: "erased",
      note: "On-chain anchors are immutable; off-chain linkability removed.",
      nextToken,
      erase_completion: {
        requested_at: completion.requestedAt,
        offchain_unlink_done: completion.offchainUnlinkDone,
        purge_pending: completion.purgePending,
        purge_pending_count: completion.purgePendingCount,
        purge_dead_lettered_count: completion.purgeDeadLetteredCount,
        linked_residual_count: completion.linkedResidualCount,
        linked_active_residual_count: completion.linkedActiveResidualCount,
        inventory_truncated: completion.inventoryTruncated
      }
    });
  });

  app.get("/v1/privacy/erase-status", async (request, reply) => {
    const context = await getDsrContext(request, reply);
    if (!context) return;
    const completion = await getEraseCompletionState(context.didHash, context.legacyHash);
    return reply.send({
      subject: { did_hash: context.didHash },
      erase_completion: {
        requested_at: completion.requestedAt,
        offchain_unlink_done: completion.offchainUnlinkDone,
        purge_pending: completion.purgePending,
        purge_pending_count: completion.purgePendingCount,
        purge_dead_lettered_count: completion.purgeDeadLetteredCount,
        linked_residual_count: completion.linkedResidualCount,
        linked_active_residual_count: completion.linkedActiveResidualCount,
        inventory_truncated: completion.inventoryTruncated,
        pending_table_counts: completion.pendingTableCounts
      }
    });
  });

};
