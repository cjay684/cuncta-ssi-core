import { z } from "zod";
import { getComplianceProfile } from "@cuncta/policy-profiles";
import type { ComplianceProfile, ComplianceProfileFlags } from "@cuncta/policy-profiles";
import { config } from "./config.js";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const OriginMapSchema = z.record(z.string().min(1), z.string().min(1));

const parseOriginMap = () => {
  const raw = config.COMPLIANCE_PROFILE_ORIGIN_MAP_JSON?.trim();
  if (!raw) return {} as Record<string, string>;
  try {
    return OriginMapSchema.parse(JSON.parse(raw) as unknown);
  } catch {
    if (config.NODE_ENV === "production") {
      throw new Error("compliance_profile_origin_map_invalid");
    }
    return {} as Record<string, string>;
  }
};

const originMap = parseOriginMap();

const normalizeOrigin = (value: string) => {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
};

export const selectComplianceProfile = (context?: Record<string, unknown>): ComplianceProfile => {
  const explicit =
    isRecord(context) && typeof context.profile_id === "string" ? context.profile_id.trim() : "";
  const explicitProfile = explicit ? getComplianceProfile(explicit) : null;
  if (explicitProfile) return explicitProfile;

  const origin =
    isRecord(context) && typeof context.verifier_origin === "string"
      ? normalizeOrigin(context.verifier_origin)
      : "";
  if (origin) {
    const mappedId = originMap[origin];
    const mappedProfile = mappedId ? getComplianceProfile(mappedId) : null;
    if (mappedProfile) return mappedProfile;
  }

  const fallbackId = String(config.COMPLIANCE_PROFILE_DEFAULT ?? "default").trim() || "default";
  return getComplianceProfile(fallbackId) ?? (getComplianceProfile("default") as ComplianceProfile);
};

export const flagsFromRequirements = (input: {
  profile: ComplianceProfile;
  requirementsFlags?: Partial<ComplianceProfileFlags> | null;
}): ComplianceProfileFlags => {
  // Requirements may include flags already computed by policy-service; treat them as hints.
  // We still OR them with profile flags so we never accidentally loosen in verifier.
  const rf = input.requirementsFlags ?? {};
  const pf = input.profile.flags ?? ({} as ComplianceProfileFlags);
  return {
    enforceOriginAudience: Boolean(pf.enforceOriginAudience || rf.enforceOriginAudience),
    failClosedDependencies: Boolean(pf.failClosedDependencies || rf.failClosedDependencies),
    statusListStrict: Boolean(pf.statusListStrict || rf.statusListStrict)
  };
};
