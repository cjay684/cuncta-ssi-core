import { z } from "zod";

// Strict scope_json contract for Aura portability.
// - No raw identifiers persisted server-side (hash-only binding in DB).
// - Wallet supplies scope_json at token redemption time; issuer validates shape + size.

const MAX_SCOPE_JSON_BYTES = 512;

const scopeDomainSchema = z
  .object({
    domain: z.enum(["marketplace", "social"])
  })
  .strict();

const scopeSpaceSchema = z
  .object({
    space_id: z.string().uuid()
  })
  .strict();

export type AuraScope =
  | { kind: "domain"; domain: "marketplace" | "social" }
  | { kind: "space"; space_id: string };

export const parseAuraScopeJson = (raw: string): AuraScope => {
  const text = String(raw ?? "");
  if (!text || text.length < 2) {
    throw new Error("scope_json_missing");
  }
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > MAX_SCOPE_JSON_BYTES) {
    throw new Error("scope_json_too_large");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("scope_json_invalid");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("scope_json_invalid");
  }
  // Accept exactly one of the strict shapes.
  const domainTry = scopeDomainSchema.safeParse(parsed);
  if (domainTry.success) {
    return { kind: "domain", domain: domainTry.data.domain };
  }
  const spaceTry = scopeSpaceSchema.safeParse(parsed);
  if (spaceTry.success) {
    return { kind: "space", space_id: spaceTry.data.space_id };
  }
  throw new Error("scope_json_invalid");
};

export const auraScopeToDerivedDomain = (scope: AuraScope) => {
  if (scope.kind === "domain") return scope.domain;
  return `space:${scope.space_id}`;
};

export const validateAuraScopeAgainstRuleDomainPattern = (input: {
  ruleDomainPattern: string;
  scope: AuraScope;
  derivedDomain: string;
}) => {
  const pattern = String(input.ruleDomainPattern ?? "").trim();
  if (!pattern) {
    throw new Error("scope_rule_domain_missing");
  }
  // Exact domain rule must use {domain} scopes.
  if (!pattern.endsWith("*")) {
    if (input.scope.kind !== "domain") {
      throw new Error("scope_kind_mismatch");
    }
    if (input.derivedDomain !== pattern) {
      throw new Error("scope_domain_mismatch");
    }
    return;
  }

  // Prefix-pattern rules must use {space_id} scopes (for now we only support `space:*`).
  const prefix = pattern.slice(0, -1);
  if (prefix !== "space:") {
    throw new Error("scope_pattern_unsupported");
  }
  if (input.scope.kind !== "space") {
    throw new Error("scope_kind_mismatch");
  }
  if (!input.derivedDomain.startsWith(prefix)) {
    throw new Error("scope_domain_mismatch");
  }
};
