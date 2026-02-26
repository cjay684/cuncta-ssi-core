import { importJWK, jwtVerify } from "jose";
import { z } from "zod";
import { canonicalizeJson, hashCanonicalJson } from "@cuncta/shared";
import type { TrustRegistry, TrustRegistrySignedBundle, TrustMark } from "./types.js";

// eslint-disable-next-line @typescript-eslint/consistent-type-imports
import registryBundle from "../registries/default/bundle.json" with { type: "json" };

const TrustedIssuerSchema = z.object({
  did: z.string().min(8),
  marks: z.array(z.string().min(1)).default([]),
  name: z.string().min(1).optional(),
  jwks_uri: z.string().url().optional()
});

const TrustedVerifierSchema = z.object({
  did: z.string().min(8),
  marks: z.array(z.string().min(1)).default([]),
  origin: z.string().min(8).optional(),
  name: z.string().min(1).optional()
});

const RegistrySchema = z.object({
  registry_id: z.string().min(1),
  created_at: z.string().min(10),
  issuers: z.array(TrustedIssuerSchema).default([]),
  verifiers: z.array(TrustedVerifierSchema).default([])
});

const BundleSchema = z.object({
  registry: RegistrySchema,
  signature_jws: z.string().min(10),
  verify_jwk: z.record(z.string(), z.unknown())
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const verifyBundle = async (bundle: TrustRegistrySignedBundle): Promise<TrustRegistry> => {
  const registry = bundle.registry;
  const registryHash = hashCanonicalJson(registry);
  const key = await importJWK(bundle.verify_jwk as never, "EdDSA");
  const { payload } = await jwtVerify(bundle.signature_jws, key, { algorithms: ["EdDSA"] });
  if (!isRecord(payload)) {
    throw new Error("trust_registry_signature_invalid");
  }
  if (payload.registry_id !== registry.registry_id) {
    throw new Error("trust_registry_signature_mismatch");
  }
  if (payload.hash !== registryHash) {
    throw new Error("trust_registry_hash_mismatch");
  }
  return registry;
};

let cached: TrustRegistry | null = null;

export const loadTrustRegistry = async () => {
  if (cached) return cached;
  const bundle = BundleSchema.parse(registryBundle) as unknown as TrustRegistrySignedBundle;
  const registry = await verifyBundle(bundle);
  // Defensive: ensure no accidental PII fields are smuggled in.
  const text = canonicalizeJson(registry);
  if (text.includes("email") || text.includes("phone")) {
    throw new Error("trust_registry_pii_field_forbidden");
  }
  cached = registry;
  return registry;
};

export const isTrustedIssuer = async (input: { issuerDid: string; requireMark?: TrustMark }) => {
  const registry = await loadTrustRegistry();
  const entry = registry.issuers.find((i) => i.did === input.issuerDid);
  if (!entry) return { trusted: false as const };
  if (input.requireMark) {
    if (!entry.marks.includes(input.requireMark)) return { trusted: false as const };
  }
  return { trusted: true as const };
};

