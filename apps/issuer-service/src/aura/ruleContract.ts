export type AuraRuleRow = {
  rule_id: string;
  domain: string;
  output_vct: string;
  rule_logic: unknown;
  enabled: boolean;
  version: number;
  rule_signature?: string | null;
};

export const parseRuleLogic = (row: { rule_logic?: unknown }): Record<string, unknown> => {
  const raw = row.rule_logic;
  if (!raw) return {};
  if (typeof raw === "string") {
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {};
    }
  }
  if (typeof raw === "object") {
    return raw as Record<string, unknown>;
  }
  return {};
};

export const getRulePurpose = (ruleLogic: Record<string, unknown>) => {
  const purpose = typeof ruleLogic.purpose === "string" ? ruleLogic.purpose.trim() : "";
  return purpose;
};

export const isDomainPatternValid = (value: string) => {
  const trimmed = value.trim();
  if (!trimmed) return { ok: false as const, reason: "domain_missing" };
  if (trimmed === "*") return { ok: false as const, reason: "domain_wildcard_forbidden" };
  // Allow exact domain OR prefix pattern `namespace:*` (still domain-scoped).
  if (trimmed.endsWith("*")) {
    const prefix = trimmed.slice(0, -1);
    if (!prefix.endsWith(":")) {
      return { ok: false as const, reason: "domain_pattern_invalid" };
    }
    if (prefix.length < 3) {
      return { ok: false as const, reason: "domain_pattern_too_broad" };
    }
  }
  return { ok: true as const };
};

export const ruleAppliesToDomain = (ruleDomain: string, domain: string) => {
  const rd = ruleDomain.trim();
  const d = domain.trim();
  if (!rd || !d) return false;
  if (rd === d) return true;
  if (rd.endsWith("*") && rd !== "*") {
    const prefix = rd.slice(0, -1);
    return d.startsWith(prefix);
  }
  return false;
};

