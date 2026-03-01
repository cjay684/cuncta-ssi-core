import { isTrustedIssuer } from "@cuncta/trust-registry";

export type IssuerRule =
  | { mode: "allowlist"; allowed?: string[] }
  | { mode: "env"; env?: string }
  | { mode: "trust_registry"; registry_id?: string; trust_mark?: string };

export const checkIssuerRule = async (input: {
  issuerDid: string;
  rule: IssuerRule;
}): Promise<
  | { ok: true }
  | {
      ok: false;
      reason: "issuer_not_allowed" | "issuer_not_trusted" | "issuer_trust_registry_unavailable";
    }
> => {
  const rule = input.rule;
  if (rule.mode === "allowlist") {
    const allowed = rule.allowed ?? [];
    if (allowed.includes("*") || allowed.includes(input.issuerDid)) return { ok: true };
    return { ok: false, reason: "issuer_not_allowed" };
  }
  if (rule.mode === "env") {
    const envDid = rule.env ? process.env[rule.env] : undefined;
    if (envDid && envDid === input.issuerDid) return { ok: true };
    return { ok: false, reason: "issuer_not_allowed" };
  }

  const registryId = String(rule.registry_id ?? "default");
  if (registryId !== "default") {
    return { ok: false, reason: "issuer_trust_registry_unavailable" };
  }
  try {
    const mark = rule.trust_mark;
    const trusted = await isTrustedIssuer({
      issuerDid: input.issuerDid,
      requireMark: typeof mark === "string" && mark.length > 0 ? mark : undefined
    });
    if (!trusted.trusted) return { ok: false, reason: "issuer_not_trusted" };
    return { ok: true };
  } catch {
    return { ok: false, reason: "issuer_trust_registry_unavailable" };
  }
};
