import { randomUUID } from "node:crypto";
import { getDb } from "../db.js";
import { hashCanonicalJson } from "@cuncta/shared";
import { log } from "../log.js";
import { metrics } from "../metrics.js";
import { config } from "../config.js";
import { getPrivacyStatus } from "../privacy/restrictions.js";
import { ensureAuraRuleIntegrity } from "./auraIntegrity.js";

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

const tierRank: Record<string, number> = { bronze: 0, silver: 1, gold: 2 };

const workerStatus = {
  lastRunAt: null as string | null,
  lastError: null as string | null
};

let auraWorkerHalted = false;

export const getAuraWorkerStatus = () => ({ ...workerStatus });
export const isAuraWorkerHalted = () => auraWorkerHalted;

const computeTier = (score: number, ruleLogic: Record<string, unknown>) => {
  const scoreRule = (ruleLogic.score as Record<string, unknown>) ?? {};
  const minSilver = parseNumber(scoreRule.min_silver, 5);
  const minGold = parseNumber(scoreRule.min_gold, 12);
  if (score >= minGold) return "gold";
  if (score >= minSilver) return "silver";
  return "bronze";
};

const clampByDiversity = (tier: string, diversity: number, ruleLogic: Record<string, unknown>) => {
  const diversityRule = (ruleLogic.diversity as Record<string, unknown>) ?? {};
  const minSilver = parseNumber(diversityRule.min_for_silver, 5);
  const minGold = parseNumber(diversityRule.min_for_gold, 12);
  if (diversity < minSilver) return "bronze";
  if (diversity < minGold && tier === "gold") return "silver";
  return tier;
};

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
    const applicable = rules.filter((rule) => rule.domain === domain || rule.domain === "*");
    if (!applicable.length) continue;

    for (const rule of applicable) {
      const ruleLogic =
        typeof rule.rule_logic === "string"
          ? (JSON.parse(rule.rule_logic) as Record<string, unknown>)
          : (rule.rule_logic as Record<string, unknown>);
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
      let tier = computeTier(score, ruleLogic);
      tier = clampByDiversity(tier, diversity, ruleLogic);
      const minTier = typeof ruleLogic.min_tier === "string" ? ruleLogic.min_tier : "bronze";
      const diversityMin = parseNumber(ruleLogic.diversity_min, 0);
      const context = {
        tier,
        domain,
        score: Number(score.toFixed(4)),
        diversity,
        now: new Date().toISOString()
      };

      await db("aura_state")
        .insert({
          subject_did_hash: subjectDidHash,
          domain,
          state: {
            score: context.score,
            diversity: context.diversity,
            tier: context.tier,
            window_days: windowDays,
            last_signal_at: windowSignals.at(-1)?.created_at ?? context.now
          },
          updated_at: context.now
        })
        .onConflict(["subject_did_hash", "domain"])
        .merge({
          state: {
            score: context.score,
            diversity: context.diversity,
            tier: context.tier,
            window_days: windowDays,
            last_signal_at: windowSignals.at(-1)?.created_at ?? context.now
          },
          updated_at: context.now
        });

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

      if (diversity >= diversityMin && tierRank[tier] >= (tierRank[minTier] ?? 0)) {
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
