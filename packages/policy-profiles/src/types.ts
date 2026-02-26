export type ComplianceProfileId = "default" | "uk" | "eu" | (string & {});

export type ComplianceProfileFlags = {
  // Enforce `origin:` audience binding (fail-closed).
  enforceOriginAudience: boolean;
  // Treat dependency failures (policy fetch, DID resolve) as DENY with generic reason.
  failClosedDependencies: boolean;
  // Require status-list validation to be strict (no soft-allow on fetch failures).
  statusListStrict: boolean;
};

export type ComplianceProfileOverlay = {
  // Overlay is intentionally limited to "can only get stricter" knobs.
  binding?: { require?: true; mode?: "kb-jwt" };
  requirements?: {
    // If set, enforce revocation is required for all requirements unless explicitly marked required already.
    revocationRequired?: true;
  };
};

export type ComplianceProfile = {
  profile_id: ComplianceProfileId;
  description: string;
  flags: ComplianceProfileFlags;
  overlay?: ComplianceProfileOverlay;
};

