import { z } from "zod";
import type { ComplianceProfile, ComplianceProfileId } from "./types.js";

const ProfileSchema = z.object({
  profile_id: z.string().min(1),
  description: z.string().min(1),
  flags: z.object({
    enforceOriginAudience: z.boolean(),
    failClosedDependencies: z.boolean(),
    statusListStrict: z.boolean()
  }),
  overlay: z
    .object({
      binding: z
        .object({
          require: z.literal(true).optional(),
          mode: z.literal("kb-jwt").optional()
        })
        .optional(),
      requirements: z
        .object({
          revocationRequired: z.literal(true).optional()
        })
        .optional()
    })
    .optional()
});

// Bundled JSON imports keep this data-driven, but ship it as part of the package
// so production does not need filesystem access.
import defaultProfile from "../profiles/default.json" with { type: "json" };
import ukProfile from "../profiles/uk.json" with { type: "json" };
import euProfile from "../profiles/eu.json" with { type: "json" };

const parsed = [
  ProfileSchema.parse(defaultProfile),
  ProfileSchema.parse(ukProfile),
  ProfileSchema.parse(euProfile)
] as unknown as ComplianceProfile[];

const byId = new Map<string, ComplianceProfile>();
for (const p of parsed) {
  byId.set(p.profile_id, p);
}

export const listComplianceProfiles = (): ComplianceProfile[] => parsed.slice();

export const getComplianceProfile = (profileId: ComplianceProfileId): ComplianceProfile | null => {
  return byId.get(profileId) ?? null;
};
