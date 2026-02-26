import { z } from "zod";
import { getComplianceProfile } from "@cuncta/policy-profiles";
import type { ComplianceProfile, ComplianceProfileFlags } from "@cuncta/policy-profiles";
import type { PolicyLogic } from "./policy/evaluate.js";
import { config } from "./config.js";

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const OriginMapSchema = z.record(z.string().min(1), z.string().min(1));

const parseOriginMap = () => {
  const raw = config.COMPLIANCE_PROFILE_ORIGIN_MAP_JSON?.trim();
  if (!raw) return {} as Record<string, string>;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return OriginMapSchema.parse(parsed);
  } catch {
    // Fail-closed in production: bad mapping is treated as config error.
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

const mergeFlags = (base?: Partial<ComplianceProfileFlags>, overlay?: Partial<ComplianceProfileFlags>) => ({
  enforceOriginAudience: Boolean(overlay?.enforceOriginAudience ?? base?.enforceOriginAudience ?? true),
  failClosedDependencies: Boolean(overlay?.failClosedDependencies ?? base?.failClosedDependencies ?? true),
  statusListStrict: Boolean(overlay?.statusListStrict ?? base?.statusListStrict ?? true)
});

// Overlay is only allowed to tighten (never loosen) the policy semantics.
export const applyComplianceProfileOverlay = (input: {
  profile: ComplianceProfile;
  logic: PolicyLogic;
}): { logic: PolicyLogic; flags: ComplianceProfileFlags } => {
  const profile = input.profile;
  const overlay = profile.overlay ?? {};

  const next: PolicyLogic = {
    ...input.logic,
    binding: input.logic.binding ? { ...input.logic.binding } : undefined,
    requirements: input.logic.requirements.map((r) => ({ ...r })),
    obligations: input.logic.obligations.map((o) => ({ ...o }))
  };

  if (overlay.binding?.require) {
    next.binding = { ...(next.binding ?? { mode: "kb-jwt", require: true }), require: true };
  }
  if (overlay.binding?.mode) {
    // Only allow moving toward kb-jwt; never relax to nonce.
    next.binding = { ...(next.binding ?? { mode: "kb-jwt", require: true }), mode: "kb-jwt" };
  }

  if (overlay.requirements?.revocationRequired) {
    for (const req of next.requirements) {
      req.revocation = { ...(req.revocation ?? { required: true }), required: true };
    }
  }

  return {
    logic: next,
    flags: mergeFlags(profile.flags, undefined)
  };
};

