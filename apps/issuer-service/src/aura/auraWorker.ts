import { randomUUID } from "node:crypto";
import { getDb } from "../db.js";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { config } from "../config.js";
import { getPrivacyStatus } from "../privacy/restrictions.js";
import { ensureAuraRuleIntegrity } from "./auraIntegrity.js";
import { parseRuleLogic, ruleAppliesToDomain } from "./ruleContract.js";
import { clampTierByDiversity, computeTierFromScore, tierLevelForName } from "./tier.js";

type AuraRule = {
  rule_id: string;
  domain: string;
  output_vct: string;
  rule_logic: Record<string, unknown>;
  enabled: boolean;
  version: number;
  rule_signature?: string | null;
};

const parseNumber = (value: unknown, fallback: number) =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;

const workerStatus = {
  lastRunAt: null as string | null,
  lastError: null as string | null
};

let auraWorkerHalted = false;

export const getAuraWorkerStatus = () => ({ ...workerStatus });
export const isAuraWorkerHalted = () => auraWorkerHalted;

const computeScore = (
  signals: Array<Record<string, unknown>>,
  ruleLogic: Record<string, unknown>
) => {
  const counterpartyMap = new Map<string, { count: number; weightSum: number }>();
  for (const signal of signals) {
    const baseWeight = parseNumber(signal.weight, 1);
    const counterparty = (signal.counterparty_did_hash as string | undefined) ?? "none";
    const entry = counterpartyMap.get(counterparty) ?? { count: 0, weightSum: 0 };
    entry.count += 1;
    entry.weightSum += baseWeight;
    counterpartyMap.set(counterparty, entry);
  }

  const cap = parseNumber(ruleLogic.per_counterparty_cap, 0);
  const decay = parseNumber(ruleLogic.per_counterparty_decay_exponent, 0.5);
  const weights = Array.from(counterpartyMap.values()).map((entry) => {
    const effectiveCount = cap > 0 ? Math.min(entry.count, cap) : entry.count;
    const averageWeight = entry.weightSum / entry.count;
    const effectiveWeightSum = averageWeight * effectiveCount;
    return effectiveWeightSum / Math.pow(effectiveCount, decay);
  });
  const total = weights.reduce((sum, value) => sum + value, 0);
  const sorted = [...weights].sort((a, b) => b - a);
  const topTwo = sorted.slice(0, 2).reduce((sum, value) => sum + value, 0);
  const concentration = total > 0 ? topTwo / total : 0;
  const collusionThreshold = parseNumber(ruleLogic.collusion_cluster_threshold, NaN);
  const collusionMultiplier = parseNumber(ruleLogic.collusion_multiplier, NaN);
  const legacy = (ruleLogic.anti_collusion as Record<string, unknown>) ?? {};
  const threshold = Number.isNaN(collusionThreshold)
    ? parseNumber(legacy.top2_ratio, 0.6)
    : collusionThreshold;
  const multiplier = Number.isNaN(collusionMultiplier)
    ? parseNumber(legacy.multiplier, 0.7)
    : collusionMultiplier;
  const antiCollusionMultiplier = concentration > threshold ? multiplier : 1;

  const diversity = Array.from(counterpartyMap.keys()).filter((key) => key !== "none").length;
  return { score: total * antiCollusionMultiplier, diversity };
};

export const computeAuraScoreAndDiversity = computeScore;

const applyTemplate = (value: unknown, context: Record<string, string | number>): unknown => {
  if (typeof value === "string") {
    return value.replace(/\{(\w+)\}/g, (_, key: string) =>
      context[key] !== undefined ? String(context[key]) : `{${key}}`
    );
  }
  if (Array.isArray(value)) {
    return value.map((entry) => applyTemplate(entry, context));
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.keys(record).reduce<Record<string, unknown>>((acc, key) => {
      acc[key] = applyTemplate(record[key], context);
      return acc;
    }, {});
  }
  return value;
};

const buildClaims = (
  ruleLogic: Record<string, unknown>,
  context: Record<string, string | number>
) => {
  const output = (ruleLogic.output as Record<string, unknown>) ?? {};
  const claims = (output.claims as Record<string, unknown>) ?? {};
  return applyTemplate(claims, context) as Record<string, unknown>;
};

const deriveSpaceId = (domain: string): string | null => {
  if (!domain.startsWith("space:")) return null;
  const value = domain.slice("space:".length).trim();
  return value.length > 0 ? value : null;
};

export const processAuraSignalsOnce = async () => {
  const db = await getDb();
  const now = new Date().toISOString();
  workerStatus.lastRunAt = now;
  workerStatus.lastError = null;
  const rules = (await db("aura_rules").where({ enabled: true })) as AuraRule[];
  for (const rule of rules) {
    try {
      await ensureAuraRuleIntegrity(rule);
    } catch {
      throw new Error("aura_integrity_failed");
    }
  }
  if (!rules.length) return;

  const pendingSignals = (await db("aura_signals")
    .whereNull("processed_at")
    .orderBy("created_at", "asc")
    .limit(200)) as Array<Record<string, unknown>>;
  if (!pendingSignals.length) return;

  // Privacy-safe anchoring: per-run batch receipts with no subject hashes.
  // Batch hash is computed over signal event_hashes only (not published individually).
  if (config.ANCHOR_AUTH_SECRET) {
    try {
      const byDomain = new Map<string, Array<Record<string, unknown>>>();
      for (const s of pendingSignals) {
        const domain = String(s.domain ?? "");
        if (!domain) continue;
        const list = byDomain.get(domain) ?? [];
        list.push(s);
        byDomain.set(domain, list);
      }
      for (const [domain, list] of byDomain.entries()) {
        const hashes = list
          .map((s) => String(s.event_hash ?? ""))
          .filter((h) => h.length > 0)
          .sort();
        if (!hashes.length) continue;
        // Deterministic batch hash: binds the event set and the active rule versions (privacy-safe).
        const applicableRules = rules
          .filter((r) => ruleAppliesToDomain(String(r.domain ?? ""), domain))
          .map((r) => ({ rule_id: r.rule_id, output_vct: r.output_vct, version: r.version }))
          .sort((a, b) => a.rule_id.localeCompare(b.rule_id));
        const batchHash = hashCanonicalJson({
          event_hashes: hashes,
          rules: applicableRules
        });
        const windowStart = String(list[0]?.created_at ?? now);
        const windowEnd = String(list[list.length - 1]?.created_at ?? now);
        const payloadHash = hashCanonicalJson({
          event: "AURA_BATCH",
          domain,
          window_start: windowStart,
          window_end: windowEnd,
          signal_count: list.length,
          batch_hash: batchHash
        });
        await db("anchor_outbox")
          .insert({
            outbox_id: randomUUID(),
            event_type: "AURA_BATCH",
            payload_hash: payloadHash,
            payload_meta: {
              domain,
              window_start: windowStart,
              window_end: windowEnd,
              signal_count: list.length,
              batch_hash: batchHash,
              ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
                payloadHash,
                eventType: "AURA_BATCH"
              })
            },
            status: "PENDING",
            attempts: 0,
            next_retry_at: now,
            created_at: now,
            updated_at: now
          })
          .onConflict("payload_hash")
          .ignore();
      }
    } catch (error) {
      log.warn("aura.batch.anchor_failed", {
        error: error instanceof Error ? error.message : "unknown_error"
      });
    }
  }

  const grouped = new Map<string, Array<Record<string, unknown>>>();
  for (const signal of pendingSignals) {
    const subject = signal.subject_did_hash as string;
    const domain = signal.domain as string;
    const key = `${subject}::${domain}`;
    const list = grouped.get(key) ?? [];
    list.push(signal);
    grouped.set(key, list);
  }

  for (const [key, signals] of grouped.entries()) {
    const [subjectDidHash, domain] = key.split("::");
    const privacy = await getPrivacyStatus({ primary: subjectDidHash });
    if (privacy.tombstoned || privacy.restricted) {
      await db("aura_signals")
        .whereIn(
          "id",
          signals.map((signal) => signal.id as number)
        )
        .update({ processed_at: new Date().toISOString() });
      continue;
    }
    const applicable = rules.filter((rule) =>
      ruleAppliesToDomain(String(rule.domain ?? ""), domain)
    );
    if (!applicable.length) continue;

    let aggregatedState: {
      score: number;
      diversity: number;
      tier: string;
      tierLevel: number;
      windowDays: number;
      lastSignalAt: string;
      updatedAt: string;
    } | null = null;
    for (const rule of applicable) {
      const ruleLogic = parseRuleLogic(rule);
      const windowSeconds = parseNumber(ruleLogic.window_seconds, 0);
      const windowDays = parseNumber(ruleLogic.window_days, 30);
      const windowMs = windowSeconds > 0 ? windowSeconds * 1000 : windowDays * 24 * 60 * 60 * 1000;
      const since = new Date(Date.now() - windowMs).toISOString();
      const signalNames = Array.isArray(ruleLogic.signals) ? (ruleLogic.signals as string[]) : [];
      const query = db("aura_signals")
        .where({ subject_did_hash: subjectDidHash, domain })
        .andWhere("created_at", ">=", since);
      if (signalNames.length) {
        query.whereIn("signal", signalNames);
      }
      const windowSignals = (await query) as Array<Record<string, unknown>>;
      if (!windowSignals.length) continue;

      const { score, diversity } = computeScore(windowSignals, ruleLogic);
      const tierComputed = computeTierFromScore(score, ruleLogic);
      const clampedLevel = clampTierByDiversity({
        tierLevel: tierComputed.tierLevel,
        tiers: tierComputed.tiers,
        diversity,
        ruleLogic
      });
      const tier = tierComputed.tiers[clampedLevel]?.name ?? tierComputed.tier;
      const minTier = typeof ruleLogic.min_tier === "string" ? ruleLogic.min_tier : "bronze";
      const minTierLevel = tierLevelForName(minTier, tierComputed.tiers);
      const diversityMin = parseNumber(ruleLogic.diversity_min, 0);
      const context = {
        tier,
        domain,
        space_id: deriveSpaceId(domain) ?? domain,
        score: Number(score.toFixed(4)),
        diversity,
        now: new Date().toISOString()
      };

      const candidate = {
        score: context.score,
        diversity: context.diversity,
        tier: context.tier,
        tierLevel: clampedLevel,
        windowDays,
        lastSignalAt: String(windowSignals.at(-1)?.created_at ?? context.now),
        updatedAt: context.now
      };
      if (!aggregatedState) {
        aggregatedState = candidate;
      } else {
        // Non-authoritative UX state: choose the "best" across applicable rules deterministically.
        // (Higher tier wins; tie-breaker: higher score.)
        const currentLevel = (aggregatedState as { tierLevel?: number }).tierLevel ?? 0;
        if (
          candidate.tierLevel > currentLevel ||
          (candidate.tierLevel === currentLevel && candidate.score > aggregatedState.score)
        ) {
          aggregatedState = candidate;
        }
      }

      const claims = buildClaims(ruleLogic, context);
      const reasonHash = hashCanonicalJson({
        ruleId: rule.rule_id,
        outputVct: rule.output_vct,
        subjectDidHash,
        domain,
        tier: context.tier,
        score: context.score,
        diversity: context.diversity,
        windowDays,
        claims
      });

      if (diversity >= diversityMin && clampedLevel >= minTierLevel) {
        await db("aura_issuance_queue")
          .insert({
            queue_id: `aq_${randomUUID()}`,
            rule_id: rule.rule_id,
            subject_did_hash: subjectDidHash,
            domain,
            output_vct: rule.output_vct,
            reason_hash: reasonHash,
            status: "PENDING",
            created_at: context.now,
            updated_at: context.now
          })
          .onConflict(["rule_id", "subject_did_hash", "reason_hash"])
          .ignore();
      }
    }
    if (aggregatedState) {
      await db("aura_state")
        .insert({
          subject_did_hash: subjectDidHash,
          domain,
          state: {
            score: aggregatedState.score,
            diversity: aggregatedState.diversity,
            tier: aggregatedState.tier,
            window_days: aggregatedState.windowDays,
            last_signal_at: aggregatedState.lastSignalAt
          },
          updated_at: aggregatedState.updatedAt
        })
        .onConflict(["subject_did_hash", "domain"])
        .merge({
          state: {
            score: aggregatedState.score,
            diversity: aggregatedState.diversity,
            tier: aggregatedState.tier,
            window_days: aggregatedState.windowDays,
            last_signal_at: aggregatedState.lastSignalAt
          },
          updated_at: aggregatedState.updatedAt
        });
    }

    await db("aura_signals")
      .whereIn(
        "id",
        signals.map((signal) => signal.id as number)
      )
      .update({ processed_at: new Date().toISOString() });
  }
};

export const startAuraWorker = () => {
  const tick = async () => {
    try {
      if (auraWorkerHalted) {
        return;
      }
      await processAuraSignalsOnce();
      metrics.incCounter("worker_runs_total", { worker: "aura", status: "success" });
    } catch (error) {
      workerStatus.lastError = error instanceof Error ? error.message : "aura_failed";
      metrics.incCounter("worker_runs_total", { worker: "aura", status: "failed" });
      log.error("aura.worker.failed", { error });
      if (workerStatus.lastError === "aura_integrity_failed") {
        auraWorkerHalted = true;
        log.error("aura.worker.halted", { reason: "aura_integrity_failed" });
      }
    }
  };
  void tick();
  return setInterval(tick, config.AURA_WORKER_POLL_MS);
};

export const buildClaimsFromRule = (
  ruleLogic: Record<string, unknown>,
  context: Record<string, string | number>
) => buildClaims(ruleLogic, context);
