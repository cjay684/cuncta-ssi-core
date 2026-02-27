import { getDb } from "../db.js";
import { verifyAuraRuleIntegrity } from "./auraIntegrity.js";
import { parseRuleLogic, ruleAppliesToDomain } from "./ruleContract.js";
import { computeAuraScoreAndDiversity } from "./auraWorker.js";
import { clampTierByDiversity, computeTierFromScore, tierLevelForName } from "./tier.js";

const parseNumber = (value: unknown, fallback: number) =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;

export const getCapabilityRuleForScope = async (input: { outputVct: string; domain: string }) => {
  const db = await getDb();
  const rules = await db("aura_rules").where({ enabled: true, output_vct: input.outputVct });
  // Match by domain scope (exact or prefix patterns like "space:*").
  const matched = (rules as Array<Record<string, unknown>>).filter((r) =>
    ruleAppliesToDomain(String(r.domain ?? ""), input.domain)
  );
  if (matched.length !== 1) {
    // Avoid ambiguous rule selection; this also acts as "one enabled rule invariant" enforcement.
    throw new Error(matched.length === 0 ? "aura_rule_not_found" : "aura_rule_ambiguous");
  }
  const rule = matched[0] as Record<string, unknown>;
  await verifyAuraRuleIntegrity(rule as never);
  const ruleLogic = parseRuleLogic(rule);
  return { rule, ruleLogic };
};

export const checkCapabilityEligibility = async (input: {
  subjectLookupHashes: string[];
  domain: string;
  outputVct: string;
}) => {
  const db = await getDb();
  const { rule, ruleLogic } = await getCapabilityRuleForScope({
    outputVct: input.outputVct,
    domain: input.domain
  });

  const windowSeconds = parseNumber(ruleLogic.window_seconds, 0);
  const windowDays = parseNumber(ruleLogic.window_days, 30);
  const windowMs = windowSeconds > 0 ? windowSeconds * 1000 : windowDays * 24 * 60 * 60 * 1000;
  const since = new Date(Date.now() - windowMs).toISOString();
  const signalNames = Array.isArray(ruleLogic.signals) ? (ruleLogic.signals as string[]) : [];
  const query = db("aura_signals")
    .whereIn("subject_did_hash", input.subjectLookupHashes)
    .andWhere({ domain: input.domain })
    .andWhere("created_at", ">=", since)
    .orderBy("created_at", "asc");
  if (signalNames.length) {
    query.whereIn("signal", signalNames);
  }
  const windowSignals = (await query) as Array<Record<string, unknown>>;
  if (!windowSignals.length) {
    return { eligible: false as const, reason: "aura_signals_missing" };
  }

  const computed = computeAuraScoreAndDiversity(windowSignals, ruleLogic);
  const tierComputed = computeTierFromScore(computed.score, ruleLogic);
  const clampedLevel = clampTierByDiversity({
    tierLevel: tierComputed.tierLevel,
    tiers: tierComputed.tiers,
    diversity: computed.diversity,
    ruleLogic
  });
  const tier = tierComputed.tiers[clampedLevel]?.name ?? tierComputed.tier;
  const diversityMin = parseNumber(ruleLogic.diversity_min, 0);
  const minTier =
    typeof ruleLogic.min_tier === "string"
      ? ruleLogic.min_tier
      : (tierComputed.tiers[0]?.name ?? "bronze");
  const minTierLevel = tierLevelForName(minTier, tierComputed.tiers);
  const tierOk = clampedLevel >= minTierLevel;
  const diversityOk = computed.diversity >= diversityMin;
  if (!tierOk || !diversityOk) {
    return {
      eligible: false as const,
      reason: "aura_not_eligible",
      debug: {
        tier,
        tierLevel: clampedLevel,
        diversity: computed.diversity,
        score: computed.score,
        minTier,
        diversityMin
      }
    };
  }
  return {
    eligible: true as const,
    state: {
      tier,
      tierLevel: clampedLevel,
      diversity: computed.diversity,
      score: computed.score,
      lastSignalAt: String(windowSignals.at(-1)?.created_at ?? new Date().toISOString()),
      windowDays
    },
    rule: rule as Record<string, unknown>,
    ruleLogic
  };
};
