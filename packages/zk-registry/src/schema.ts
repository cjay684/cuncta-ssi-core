import { z } from "zod";

export const ProofSystemSchema = z.enum(["groth16_bn254"]);

export const FileRefSchema = z.object({
  path: z.string().min(1),
  sha256_hex: z.string().regex(/^[a-f0-9]{64}$/)
});

export const PublicInputsSchemaSchema = z.object({
  // Minimal, explicit schema: field elements encoded as decimal strings.
  // (Wallet and verifier both coerce to bigint.)
  type: z.literal("object"),
  properties: z.record(
    z.string(),
    z.object({
      type: z.enum(["string", "number", "integer"]),
      description: z.string().optional()
    })
  ),
  required: z.array(z.string()).default([])
});

export const ZkStatementDefinitionSchema = z
  .object({
    statement_id: z.string().min(1),
    version: z.string().min(1), // semver-ish
    proof_system: ProofSystemSchema,
    circuit_id: z.string().min(1),

    proving_key_ref: FileRefSchema,
    verifying_key_ref: FileRefSchema,
    wasm_ref: FileRefSchema.optional(),

    public_inputs_schema: PublicInputsSchemaSchema,
    // Deterministic mapping from snarkjs publicSignals[] to named inputs.
    public_inputs_order: z.array(z.string().min(1)).min(1),

    required_bindings: z
      .array(z.enum(["nonce", "audience", "request_hash"]))
      .refine((v) => v.includes("nonce") && v.includes("audience") && v.includes("request_hash"), {
        message: "required_bindings must include nonce, audience, request_hash"
      }),

    // Credential format and disclosure contract for carrying commitments (e.g. SD-JWT).
    credential: z.object({
      credential_config_id: z.string().min(1),
      vct: z.string().min(1),
      format: z.enum(["dc+sd-jwt", "di+bbs"]).default("dc+sd-jwt"),
      required_disclosures: z.array(z.string().min(1)).default([])
    }),

    // Credential linkage and scheme constraints used by verifier.
    credential_requirements: z.object({
      required_commitment_fields: z.array(z.string().min(1)).min(1),
      commitment_scheme_versions_allowed: z.array(z.string().min(1)).optional()
    }),

    // ZK context requirements that MUST originate from the signed request JWT.
    zk_context_requirements: z
      .object({
        current_day: z.object({ required: z.boolean().default(false) }).optional()
      })
      .default({}),

    // Issuer-side contract: claims accepted for issuance (never includes raw DOB).
    issuer_contract: z.object({
      allowed_claims: z.array(z.string().min(1)).min(1),
      required_claims: z.array(z.string().min(1)).min(1)
    }),

    // Verifier-side contract: binding/public input semantics and param constraints.
    verifier_contract: z.object({
      required_public_inputs: z.array(z.string().min(1)).min(1),
      binding_public_inputs: z.object({
        nonce: z.string().min(1),
        audience: z.string().min(1),
        request_hash: z.string().min(1)
      }),
      // Generic equality constraints between policy params and public inputs.
      param_constraints: z
        .array(
          z.object({
            param: z.string().min(1),
            public_input: z.string().min(1),
            op: z.literal("eq").default("eq")
          })
        )
        .default([]),
      // Generic equality constraints between signed request `zk_context` and public inputs.
      context_constraints: z
        .array(
          z.object({
            context_key: z.string().min(1),
            public_input: z.string().min(1),
            op: z.literal("eq").default("eq")
          })
        )
        .default([])
    }),

    // Wallet-side contract: select local witness/commitment builders without hardcoding statement IDs.
    wallet_contract: z.object({
      witness_builder_id: z.string().min(1),
      commitment_builder_id: z.string().min(1),
      witness_inputs_schema: z.record(z.string(), z.unknown()).default({})
    }),

    // Trust contract: who vouches for the committed attribute(s) behind the proof.
    // This is separate from cryptographic soundness; policies can require a minimum assurance level.
    attestation_level: z
      .enum(["self_asserted", "issuer_attested", "third_party_attested"])
      .default("self_asserted"),

    issuance: z.object({ enabled: z.boolean().default(false) }).default({ enabled: false }),

    privacy_notes: z.string().min(1),
    setup_provenance: z.enum(["dev_beacon", "ceremony_attested", "unknown"]).optional(),
    deprecated: z.boolean().optional()
  })
  .refine(
    (def) =>
      def.verifier_contract.required_public_inputs.join(",") === def.public_inputs_order.join(","),
    {
      message: "verifier_contract.required_public_inputs must match public_inputs_order"
    }
  )
  .refine(
    (def) => def.public_inputs_schema.required.every((k) => def.public_inputs_order.includes(k)),
    {
      message: "public_inputs_order must include all required public inputs"
    }
  );

export type ZkStatementDefinition = z.infer<typeof ZkStatementDefinitionSchema>;
