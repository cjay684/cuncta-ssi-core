import { z } from "zod";

export const HealthResponseSchema = z.object({
  ok: z.literal(true)
});

export type HealthResponse = z.infer<typeof HealthResponseSchema>;

export const PresentationRequestSchema = z.object({
  policyId: z.string().min(1),
  audience: z.string().min(1).optional(),
  nonce: z.string().optional()
});

export const PresentationResponseSchema = z.object({
  requestId: z.string().uuid(),
  presentationDefinition: z.unknown(),
  nonce: z.string(),
  audience: z.string(),
  requirements: z.unknown().optional()
});

export const PresentationVerifySchema = z
  .object({
    requestId: z.string().uuid(),
    sdJwtPresentation: z.string().min(10).optional(),
    presentation: z.string().min(10).optional()
  })
  .refine((value) => value.sdJwtPresentation || value.presentation, {
    message: "presentation_required"
  });

export const PresentationVerifyResponseSchema = z.object({
  valid: z.boolean(),
  claims: z.record(z.string(), z.unknown()).default({}),
  diagnostics: z.record(z.string(), z.unknown()).default({})
});

export { extractBearerToken, verifyServiceJwt } from "./serviceAuth.js";
export { createPrivateLaneEngine } from "./privateLane.js";
export { canonicalizeJson } from "./canonicalJson.js";
export { hashCanonicalJson } from "./hashing.js";
export { createSha256Pseudonymizer, createHmacSha256Pseudonymizer } from "./pseudonymizer.js";
export type { Pseudonymizer } from "./pseudonymizer.js";
export { makeErrorResponse } from "./errors.js";
export { createMetricsRegistry } from "./metrics.js";
export { signAnchorMeta } from "./anchorAuth.js";
export { OnboardingStrategySchema, parseOnboardingStrategyList } from "./onboarding.js";
export type { OnboardingStrategy } from "./onboarding.js";
