type TierDef = { name: string; min_score: number };

const parseNumber = (value: unknown, fallback: number) =>
  typeof value === "number" && Number.isFinite(value) ? value : fallback;

const normalizeTierName = (value: unknown) =>
  String(value ?? "")
    .trim()
    .toLowerCase();

export const deriveTierDefs = (ruleLogic: Record<string, unknown>): TierDef[] => {
  const score = (ruleLogic.score as Record<string, unknown>) ?? {};
  const raw = (score.tiers as unknown) ?? null;
  if (Array.isArray(raw)) {
    const parsed = raw
      .map((entry) =>
        entry && typeof entry === "object" ? (entry as Record<string, unknown>) : null
      )
      .filter(Boolean)
      .map((entry) => ({
        name: normalizeTierName(entry!.name),
        min_score: parseNumber(entry!.min_score, NaN)
      }))
      .filter((t) => t.name.length > 0 && Number.isFinite(t.min_score));
    if (parsed.length) {
      // Ensure deterministic ordering.
      return [...parsed].sort((a, b) => a.min_score - b.min_score);
    }
  }

  // Backward-compatible fallback: infer tiers from legacy score thresholds.
  const minSilver = parseNumber(score.min_silver, 5);
  const minGold = parseNumber(score.min_gold, 12);
  return [
    { name: "bronze", min_score: Number.NEGATIVE_INFINITY },
    { name: "silver", min_score: minSilver },
    { name: "gold", min_score: minGold }
  ].sort((a, b) => a.min_score - b.min_score);
};

export const tierLevelForName = (name: string, tiers: TierDef[]) => {
  const target = normalizeTierName(name);
  const index = tiers.findIndex((t) => t.name === target);
  return index === -1 ? 0 : index;
};

export const computeTierFromScore = (score: number, ruleLogic: Record<string, unknown>) => {
  const tiers = deriveTierDefs(ruleLogic);
  let chosen = tiers[0]?.name ?? "unknown";
  let chosenLevel = 0;
  for (let i = 0; i < tiers.length; i += 1) {
    const t = tiers[i]!;
    if (score >= t.min_score) {
      chosen = t.name;
      chosenLevel = i;
    }
  }
  return { tier: chosen, tierLevel: chosenLevel, tiers };
};

export const clampTierByDiversity = (input: {
  tierLevel: number;
  tiers: TierDef[];
  diversity: number;
  ruleLogic: Record<string, unknown>;
}) => {
  const diversityRule = (input.ruleLogic.diversity as Record<string, unknown> | undefined) ?? null;
  if (!diversityRule || Object.keys(diversityRule).length === 0) {
    return input.tierLevel;
  }

  // Generic legacy support: accept keys shaped like `min_for_<tierName>`.
  // Example: { min_for_silver: 2, min_for_gold: 5 }
  let maxAllowed = input.tierLevel;
  for (const [key, value] of Object.entries(diversityRule)) {
    if (!key.startsWith("min_for_")) continue;
    const tierName = key.slice("min_for_".length);
    const min = parseNumber(value, NaN);
    if (!Number.isFinite(min) || min <= 0) continue;
    const level = tierLevelForName(tierName, input.tiers);
    if (level <= 0) continue;
    if (input.diversity < min) {
      maxAllowed = Math.min(maxAllowed, level - 1);
    }
  }
  return Math.max(0, Math.min(maxAllowed, input.tiers.length - 1));
};
