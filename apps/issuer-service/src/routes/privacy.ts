import { FastifyInstance, FastifyReply } from "fastify";
import { randomBytes, randomUUID } from "node:crypto";
import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import { z } from "zod";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { log } from "../log.js";
import { sha256Hex } from "../crypto/sha256.js";
import { hashCanonicalJson, makeErrorResponse } from "@cuncta/shared";
import { getPrivacyStatus } from "../privacy/restrictions.js";
import { getDidHashes, getLookupHashes } from "../pseudonymizer.js";
import { metrics } from "../metrics.js";
import { ensureAuraRuleIntegrity } from "../aura/auraIntegrity.js";
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
  aura: z.array(z.record(z.string(), z.unknown())),
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

export const registerPrivacyRoutes = (app: FastifyInstance) => {
  app.get("/v1/internal/privacy/status", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["issuer:privacy_status"] });
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
      rateLimitsMax,
      auraSignalsCount,
      auraSignalsMax
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
        .first(),
      db("aura_signals")
        .whereIn("subject_did_hash", lookupHashes)
        .count<{ count: string }>("id as count")
        .first(),
      db("aura_signals")
        .whereIn("subject_did_hash", lookupHashes)
        .max<{ max: string }>("created_at as max")
        .first()
    ]);

    const auraState = await db("aura_state")
      .whereIn("subject_did_hash", lookupHashes)
      .select("domain", "state", "updated_at");

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
      aura: auraState.map((row) => ({
        domain: row.domain,
        state: row.state,
        updated_at: row.updated_at
      })),
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
        },
        aura_signals: {
          count: Number(auraSignalsCount?.count ?? 0),
          last_created_at: auraSignalsMax?.max ?? null
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
      await trx("aura_state").whereIn("subject_did_hash", lookup).del();
      await trx("aura_signals").whereIn("subject_did_hash", lookup).del();
      await trx("aura_issuance_queue").whereIn("subject_did_hash", lookup).del();
      await trx("obligation_events").whereIn("subject_did_hash", lookup).del();
      await trx("obligations_executions").whereIn("subject_did_hash", lookup).del();
      await trx("rate_limit_events").whereIn("subject_hash", lookup).del();
      await trx("privacy_requests").whereIn("did_hash", lookup).del();
      await trx("privacy_tokens").whereIn("did_hash", lookup).del();
      await trx("privacy_restrictions").whereIn("did_hash", lookup).del();
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

    log.info("privacy.erase", { didHash });
    metrics.incCounter("privacy_erase_total");
    await markPrivacyEraseEver();
    await bumpPrivacyEraseEpoch();
    const { nextToken } = await rotateDsrToken({
      didHash: context.didHash,
      legacyHash: context.legacyHash,
      tokenHash: context.tokenHash
    });
    return reply.send({
      status: "erased",
      note: "On-chain anchors are immutable; off-chain linkability removed.",
      nextToken
    });
  });

  app.get("/v1/aura/explain", async (request, reply) => {
    const context = await getDsrContext(request, reply);
    if (!context) return;
    const db = await getDb();
    const didHash = context.didHash;
    const status = await getPrivacyStatus({
      primary: context.didHash,
      legacy: context.legacyHash
    });
    if (status.tombstoned) {
      return reply.send({ subject: { did_hash: didHash }, aura: [], notice: "erased" });
    }

    const lookup = getLookupHashes({ primary: didHash, legacy: context.legacyHash });
    const auraStates = await db("aura_state").whereIn("subject_did_hash", lookup);
    const rules = await db("aura_rules").where({ enabled: true });
    try {
      for (const rule of rules) {
        await ensureAuraRuleIntegrity(rule);
      }
    } catch {
      return reply.code(503).send(
        makeErrorResponse("aura_integrity_failed", "Aura rules unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }
    const response = [];

    for (const stateRow of auraStates) {
      const domain = stateRow.domain as string;
      const state =
        typeof stateRow.state === "string"
          ? (JSON.parse(stateRow.state) as Record<string, unknown>)
          : (stateRow.state as Record<string, unknown>);
      const applicable = rules.filter(
        (rule: Record<string, unknown>) => rule.domain === domain || rule.domain === "*"
      );
      for (const rule of applicable) {
        const ruleLogic =
          typeof rule.rule_logic === "string"
            ? (JSON.parse(rule.rule_logic) as Record<string, unknown>)
            : (rule.rule_logic as Record<string, unknown>);
        const windowSeconds =
          typeof ruleLogic.window_seconds === "number" ? ruleLogic.window_seconds : 0;
        const windowDays = typeof ruleLogic.window_days === "number" ? ruleLogic.window_days : 30;
        const windowMs =
          windowSeconds > 0 ? windowSeconds * 1000 : windowDays * 24 * 60 * 60 * 1000;
        const since = new Date(Date.now() - windowMs).toISOString();
        const signalNames = Array.isArray(ruleLogic.signals) ? (ruleLogic.signals as string[]) : [];
        const query = db("aura_signals")
          .whereIn("subject_did_hash", lookup)
          .andWhere("domain", domain)
          .andWhere("created_at", ">=", since);
        if (signalNames.length) {
          query.whereIn("signal", signalNames);
        }
        const signals = await query;
        const counterpartyMap = new Map<string, { count: number; weightSum: number }>();
        for (const signal of signals) {
          const weight = typeof signal.weight === "number" ? signal.weight : 1;
          const counterparty = (signal.counterparty_did_hash as string | undefined) ?? "none";
          const entry = counterpartyMap.get(counterparty) ?? { count: 0, weightSum: 0 };
          entry.count += 1;
          entry.weightSum += weight;
          counterpartyMap.set(counterparty, entry);
        }
        const cap =
          typeof ruleLogic.per_counterparty_cap === "number" ? ruleLogic.per_counterparty_cap : 0;
        const decay =
          typeof ruleLogic.per_counterparty_decay_exponent === "number"
            ? ruleLogic.per_counterparty_decay_exponent
            : 0.5;
        const weights = Array.from(counterpartyMap.values()).map((entry) => {
          const effectiveCount = cap > 0 ? Math.min(entry.count, cap) : entry.count;
          const averageWeight = entry.weightSum / entry.count;
          const effectiveWeightSum = averageWeight * effectiveCount;
          return effectiveWeightSum / Math.pow(effectiveCount, decay);
        });
        const total = weights.reduce((sum, value) => sum + value, 0);
        const sorted = [...weights].sort((a, b) => b - a);
        const topTwo = sorted.slice(0, 2).reduce((sum, value) => sum + value, 0);
        const top2Ratio = total > 0 ? topTwo / total : 0;

        response.push({
          rule_id: rule.rule_id,
          rule_version: rule.version,
          domain,
          output_vct: rule.output_vct,
          state: {
            tier: state.tier ?? "bronze",
            score: state.score ?? 0,
            diversity: state.diversity ?? 0,
            window_days: state.window_days ?? windowDays
          },
          aggregates: {
            signal_count: signals.length,
            diversity: Array.from(counterpartyMap.keys()).filter((key) => key !== "none").length,
            top2_ratio: Number(top2Ratio.toFixed(4))
          },
          thresholds: {
            min_silver: (ruleLogic.score as Record<string, unknown>)?.min_silver ?? 5,
            min_gold: (ruleLogic.score as Record<string, unknown>)?.min_gold ?? 12,
            diversity_min: ruleLogic.diversity_min ?? 0,
            collusion_threshold:
              ruleLogic.collusion_cluster_threshold ??
              (ruleLogic.anti_collusion as Record<string, unknown>)?.top2_ratio ??
              0.6,
            collusion_multiplier:
              ruleLogic.collusion_multiplier ??
              (ruleLogic.anti_collusion as Record<string, unknown>)?.multiplier ??
              0.7,
            min_tier: ruleLogic.min_tier ?? "bronze"
          }
        });
      }
    }

    return reply.send({
      subject: { did_hash: didHash },
      generated_at: new Date().toISOString(),
      aura: response
    });
  });
};
