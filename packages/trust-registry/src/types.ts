export type TrustRegistryId = string & {};

export type TrustMark = string & {};

export type TrustedIssuer = {
  did: string;
  marks: TrustMark[];
  // Optional metadata (display only; not used for cryptographic validation).
  name?: string;
  jwks_uri?: string;
};

export type TrustedVerifier = {
  did: string;
  marks: TrustMark[];
  // Optional relying party origin for UX and origin-bound policy selection.
  origin?: string;
  name?: string;
};

export type TrustRegistry = {
  registry_id: TrustRegistryId;
  created_at: string;
  issuers: TrustedIssuer[];
  verifiers: TrustedVerifier[];
};

export type TrustRegistrySignedBundle = {
  registry: TrustRegistry;
  // JWS over `{ registry_id, hash, iat }` with `hash=sha256(canonicalJson(registry))`.
  signature_jws: string;
  verify_jwk: Record<string, unknown>;
};

