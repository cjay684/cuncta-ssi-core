import { FastifyInstance } from "fastify";
import { z } from "zod";
import { sha256Hex } from "../crypto/sha256.js";
import { getDb } from "../db.js";
import { issueCredential, revokeCredential } from "../issuer/issuance.js";
import { buildClaimsFromRule } from "../aura/auraWorker.js";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { randomUUID } from "node:crypto";
import { requireServiceAuth } from "../auth.js";
import { config } from "../config.js";
import { makeErrorResponse } from "@cuncta/shared";
import { getPrivacyStatus } from "../privacy/restrictions.js";
import { getDidHashes, getLookupHashes } from "../pseudonymizer.js";
import { ensureAuraRuleIntegrity } from "../aura/auraIntegrity.js";

const claimSchema = z.object({
  subjectDid: z.string().min(3),
  output_vct: z.string().min(3)
});

const checkAuraClaimRateLimit = async (lookupHashes: string[], subjectHash: string) => {
  const db = await getDb();
  const windowSeconds = 60;
  const max = 10;
  const since = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const countRow = await db("rate_limit_events")
    .whereIn("subject_hash", lookupHashes)
    .andWhere({ action_id: "aura.claim" })
    .andWhere("created_at", ">=", since)
    .count<{ count: string }>("id as count")
    .first();
  const count = Number(countRow?.count ?? 0);
  if (count >= max) {
    return { allowed: false };
  }
  await db("rate_limit_events").insert({
    subject_hash: subjectHash,
    action_id: "aura.claim",
    created_at: new Date().toISOString()
  });
  return { allowed: true };
};

export const registerAuraRoutes = (app: FastifyInstance) => {
  app.post("/v1/aura/claim", async (request, reply) => {
    await requireServiceAuth(request, reply, { requiredScopes: ["issuer:aura_claim"] });
    if (reply.sent) return;
    const requestId = (request as { requestId?: string }).requestId;
    const serviceSecret =
      config.SERVICE_JWT_SECRET_ISSUER ??
      (config.ALLOW_LEGACY_SERVICE_JWT_SECRET ? config.SERVICE_JWT_SECRET : undefined);
    if (!serviceSecret && config.NODE_ENV === "production") {
      return reply.code(403).send(
        makeErrorResponse("invalid_request", "Service auth required", {
          devMode: config.DEV_MODE
        })
      );
    }
    const body = claimSchema.parse(request.body);
    const db = await getDb();
    const hashes = getDidHashes(body.subjectDid);
    const subjectHash = hashes.primary;
    const lookupHashes = getLookupHashes(hashes);
    const privacy = await getPrivacyStatus(hashes);
    if (privacy.tombstoned || privacy.restricted) {
      return reply.code(403).send(
        makeErrorResponse("invalid_request", "Restricted subject", {
          devMode: config.DEV_MODE
        })
      );
    }
    const rate = await checkAuraClaimRateLimit(lookupHashes, subjectHash);
    if (!rate.allowed) {
      return reply.code(429).send(
        makeErrorResponse("rate_limited", "Rate limited", {
          devMode: config.DEV_MODE
        })
      );
    }

    const queueResult = await db.transaction(async (trx) => {
      const row = await trx("aura_issuance_queue")
        .whereIn("subject_did_hash", lookupHashes)
        .andWhere({ output_vct: body.output_vct })
        .orderBy("created_at", "desc")
        .forUpdate()
        .first();
      if (!row) return null;
      let claimed = false;
      if (row.status === "PENDING") {
        const updated = await trx("aura_issuance_queue")
          .where({ queue_id: row.queue_id, status: "PENDING" })
          .update({ status: "PROCESSING", updated_at: new Date().toISOString() });
        claimed = updated > 0;
      }
      return { row, claimed };
    });
    if (!queueResult) {
      return reply.code(404).send(
        makeErrorResponse("aura_not_ready", "Aura not ready", {
          devMode: config.DEV_MODE
        })
      );
    }
    const queue = queueResult.row;
    if (queue.status === "ISSUED") {
      return reply.send({
        output_vct: body.output_vct,
        credential: null,
        eventId: queue.issuance_event_id ?? null,
        credentialFingerprint: queue.credential_fingerprint ?? null,
        status: "ALREADY_ISSUED"
      });
    }
    if (queue.status !== "PENDING" || !queueResult.claimed) {
      return reply.code(409).send(
        makeErrorResponse("invalid_request", "Aura claim unavailable", {
          details: `status=${queue.status}`,
          devMode: config.DEV_MODE
        })
      );
    }

    const rule = await db("aura_rules").where({ rule_id: queue.rule_id, enabled: true }).first();
    if (!rule) {
      return reply.code(404).send(
        makeErrorResponse("internal_error", "Aura rule missing", {
          devMode: config.DEV_MODE
        })
      );
    }
    try {
      await ensureAuraRuleIntegrity(rule);
    } catch {
      return reply.code(503).send(
        makeErrorResponse("aura_integrity_failed", "Aura rules unavailable", {
          devMode: config.DEV_MODE
        })
      );
    }

    const stateRow = await db("aura_state")
      .whereIn("subject_did_hash", lookupHashes)
      .andWhere({ domain: queue.domain })
      .first();
    if (!stateRow) {
      return reply.code(404).send(
        makeErrorResponse("internal_error", "Aura state missing", {
          devMode: config.DEV_MODE
        })
      );
    }

    const state =
      typeof stateRow.state === "string"
        ? (JSON.parse(stateRow.state) as Record<string, unknown>)
        : (stateRow.state as Record<string, unknown>);
    const context = {
      tier: String(state.tier ?? "bronze"),
      domain: String(queue.domain),
      score: Number(state.score ?? 0),
      diversity: Number(state.diversity ?? 0),
      now: new Date().toISOString()
    };
    const ruleLogic =
      typeof rule.rule_logic === "string"
        ? (JSON.parse(rule.rule_logic) as Record<string, unknown>)
        : (rule.rule_logic as Record<string, unknown>);
    const claims = buildClaimsFromRule(ruleLogic, context);

    try {
      const existing = await db("issuance_events")
        .where({ vct: body.output_vct })
        .whereIn("subject_did_hash", lookupHashes)
        .orderBy("issued_at", "desc");
      for (const record of existing) {
        await revokeCredential({ eventId: record.event_id as string });
      }

      const result = await issueCredential({
        subjectDid: body.subjectDid,
        vct: body.output_vct,
        claims
      });

      await db("aura_issuance_queue").where({ queue_id: queue.queue_id }).update({
        status: "ISSUED",
        issued_at: new Date().toISOString(),
        issuance_event_id: result.eventId,
        credential_fingerprint: result.credentialFingerprint,
        updated_at: new Date().toISOString()
      });

      const anchorPayloadHash = hashCanonicalJson({
        event: "AURA_DERIVED",
        outputVct: body.output_vct,
        subjectHash,
        tier: context.tier,
        eventId: result.eventId,
        issuedAt: new Date().toISOString()
      });
      if (!config.ANCHOR_AUTH_SECRET) {
        return reply.code(503).send(
          makeErrorResponse("internal_error", "Anchor auth unavailable", {
            devMode: config.DEV_MODE
          })
        );
      }
      await db("anchor_outbox")
        .insert({
          outbox_id: randomUUID(),
          event_type: "AURA_DERIVED",
          payload_hash: anchorPayloadHash,
          payload_meta: {
            output_vct_hash: sha256Hex(body.output_vct),
            subject_did_hash: subjectHash,
            event_id_hash: sha256Hex(result.eventId),
            ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
              payloadHash: anchorPayloadHash,
              eventType: "AURA_DERIVED"
            })
          },
          status: "PENDING",
          attempts: 0,
          next_retry_at: new Date().toISOString(),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        .onConflict("payload_hash")
        .ignore();

      return reply.send({
        output_vct: body.output_vct,
        credential: result.credential,
        eventId: result.eventId,
        credentialFingerprint: result.credentialFingerprint,
        status: "ISSUED"
      });
    } catch (error) {
      await db("aura_issuance_queue")
        .where({ queue_id: queue.queue_id })
        .update({
          status: "FAILED",
          error_code: error instanceof Error ? error.message.slice(0, 120) : "issue_failed",
          updated_at: new Date().toISOString()
        });
      return reply.code(500).send(
        makeErrorResponse("internal_error", "Aura issue failed", {
          devMode: config.DEV_MODE,
          debug: config.DEV_MODE
            ? {
                cause: error instanceof Error ? error.message : "Error",
                hint: `request=${requestId}`
              }
            : undefined
        })
      );
    }
  });
};
