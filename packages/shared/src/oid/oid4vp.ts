import { z } from "zod";

// CUNCTA's minimal-but-strict OID4VP request object.
// Goal: prevent subtle drift between verifier + wallet.
export const Oid4vpRequirementSchema = z
  .object({
    vct: z.string().min(1),
    formats: z.array(z.string().min(1)).default(["dc+sd-jwt"]),
    zk_predicates: z
      .array(
        z.object({
          id: z.string().min(1),
          params: z.record(z.string(), z.unknown()).optional()
        })
      )
      .default([]),
    disclosures: z.array(z.string()).default([]),
    predicates: z
      .array(
        z.object({
          path: z.string().min(1),
          op: z.string().optional(),
          value: z.unknown().optional()
        })
      )
      .optional()
  })
  .passthrough();

export const Oid4vpPresentationDefinitionSchema = z
  .object({
    id: z.string().min(1),
    input_descriptors: z.array(
      z
        .object({
          id: z.string().min(1),
          format: z.record(z.string(), z.unknown()).optional(),
          disclosures: z.array(z.string()).optional()
        })
        .passthrough()
    )
  })
  .passthrough();

export const Oid4vpRequestObjectSchema = z
  .object({
    action: z.string().min(1),
    nonce: z.string().min(10),
    audience: z.string().min(3),
    expires_at: z.string().min(10),
    // Signed request JWT (canonical, strict-mode wallet verifies via iss/.well-known/jwks.json).
    request_jwt: z.string().min(10).optional(),
    // Standards-mode: request_uri indirection (gateway enforces one-time semantics via hash-only store).
    request_uri: z.string().url().optional(),
    // Standards-mode: opaque correlation token returned to client and echoed back on response.
    state: z.string().min(6).optional(),
    // HAIP / client identity hint (optional; origin binding is enforced via `audience` semantics today).
    client_id: z.string().min(3).optional(),
    client_id_scheme: z.string().min(3).optional(),
    // Future: allow response_uri/response_mode without making them mandatory today.
    response_uri: z.string().url().optional(),
    response_mode: z.string().min(1).optional(),
    response_type: z.string().min(1).optional(),
    requirements: z.array(Oid4vpRequirementSchema),
    presentation_definition: Oid4vpPresentationDefinitionSchema,
    // ZK helpers (platform extension; included in signed request_jwt as well when present).
    zk_context: z.record(z.string(), z.unknown()).optional()
  })
  .strict();

export type Oid4vpRequestObject = z.infer<typeof Oid4vpRequestObjectSchema>;

