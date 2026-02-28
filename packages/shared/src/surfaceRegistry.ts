import { existsSync, readFileSync } from "node:fs";
import { compactVerify, importJWK, type JWK } from "jose";
import { canonicalizeJson } from "./canonicalJson.js";

// Canonicalization version pinning for the signed Surface Registry bundle.
// Increment ONLY when canonicalization logic changes.
export const SURFACE_REGISTRY_CANON_VERSION = 1 as const;

export type SurfaceKind = "public" | "internal" | "admin" | "dev_test_only";

export type SurfaceAuth = {
  requiredScopes?: string[];
  requireAdminScope?: string[];
};

export type SurfaceProbe = {
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
};

export type SurfaceRouteEntry = {
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  /**
   * Pattern syntax:
   * - `*` matches any chars (including slashes)
   * - `:param` matches one path segment
   */
  path: string;
  surface: SurfaceKind;
  /**
   * In production public posture, dev/test-only and deprecated routes are hard-disabled.
   * Defaults to 404.
   */
  disabledStatus?: 404 | 410;
  auth?: SurfaceAuth;
  probe?: SurfaceProbe;
};

export type SurfaceRegistryService = {
  id: string;
  publiclyDeployable?: boolean;
  routes: SurfaceRouteEntry[];
};

export type SurfaceRegistry = {
  schemaVersion: 1;
  services: SurfaceRegistryService[];
};

const isObject = (v: unknown): v is Record<string, unknown> => Boolean(v) && typeof v === "object";

export type SurfaceRegistryBundle = {
  registry: SurfaceRegistry;
  signature: {
    protected: string;
    payload: string;
    signature: string;
  };
};

const isNonEmptyString = (v: unknown): v is string => typeof v === "string" && v.trim().length > 0;

const parseSurfaceRegistry = (value: unknown): SurfaceRegistry => {
  if (!isObject(value) || value.schemaVersion !== 1 || !Array.isArray(value.services)) {
    throw new Error("surface_registry_invalid");
  }
  return value as SurfaceRegistry;
};

export const loadSurfaceRegistryFromFile = (absPath: string): SurfaceRegistry => {
  const raw = readFileSync(absPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  return parseSurfaceRegistry(parsed);
};

export const loadSurfaceRegistryBundleFromFile = (absPath: string): SurfaceRegistryBundle => {
  const raw = readFileSync(absPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!isObject(parsed) || !("registry" in parsed) || !("signature" in parsed)) {
    throw new Error("surface_registry_bundle_invalid");
  }
  const registry = parseSurfaceRegistry((parsed as { registry: unknown }).registry);
  const signature = (parsed as { signature: unknown }).signature;
  if (
    !isObject(signature) ||
    !isNonEmptyString(signature.protected) ||
    !isNonEmptyString(signature.payload) ||
    !isNonEmptyString(signature.signature)
  ) {
    throw new Error("surface_registry_bundle_invalid");
  }
  return {
    registry,
    signature: {
      protected: String(signature.protected),
      payload: String(signature.payload),
      signature: String(signature.signature)
    }
  };
};

const parseBase64urlJson = (encoded: string): unknown => {
  const text = Buffer.from(encoded, "base64url").toString("utf8");
  return JSON.parse(text) as unknown;
};

const parsePublicJwkFromEnv = (encoded: string): JWK => {
  const value = parseBase64urlJson(encoded) as unknown;
  if (!isObject(value)) {
    throw new Error("surface_registry_public_key_invalid");
  }
  return value as JWK;
};

const parseProtectedHeader = (encoded: string): Record<string, unknown> => {
  const value = parseBase64urlJson(encoded) as unknown;
  if (!isObject(value)) {
    throw new Error("surface_registry_signature_invalid");
  }
  return value;
};

const b64url = (input: string) => Buffer.from(input, "utf8").toString("base64url");

const protectedHeaderToDeterministicB64url = (input: {
  kid: string;
  canon: number;
  legacy: boolean;
}): string => {
  if (!isNonEmptyString(input.kid)) {
    throw new Error("surface_registry_signature_invalid");
  }
  if (!input.legacy) {
    if (!Number.isInteger(input.canon)) {
      throw new Error("surface_registry_signature_invalid");
    }
    return b64url(
      JSON.stringify({
        alg: "EdDSA",
        typ: "surface-registry+json",
        kid: input.kid,
        canon: input.canon
      })
    );
  }
  return b64url(JSON.stringify({ alg: "EdDSA", typ: "surface-registry+json", kid: input.kid }));
};

const parseAndValidateProtectedHeader = (
  protectedB64url: string
): { kid: string; canon: number; legacy: boolean } => {
  const protectedHeader = parseProtectedHeader(protectedB64url);

  const keys = Object.keys(protectedHeader);
  const isLegacy =
    keys.length === 3 && keys.includes("alg") && keys.includes("typ") && keys.includes("kid");
  const isV1Plus =
    keys.length === 4 &&
    keys.includes("alg") &&
    keys.includes("typ") &&
    keys.includes("kid") &&
    keys.includes("canon");
  if (!isLegacy && !isV1Plus) {
    throw new Error("surface_registry_signature_invalid");
  }

  if (protectedHeader.alg !== "EdDSA" || protectedHeader.typ !== "surface-registry+json") {
    throw new Error("surface_registry_signature_invalid");
  }
  const kid = String(protectedHeader.kid ?? "").trim();
  if (!isNonEmptyString(kid)) {
    throw new Error("surface_registry_signature_invalid");
  }

  const canon = (() => {
    if (isLegacy) {
      // Backwards-compat: pre-`canon` bundles are treated as canon=1.
      // Once canonicalization changes, bump SURFACE_REGISTRY_CANON_VERSION and these will fail verification.
      if (SURFACE_REGISTRY_CANON_VERSION !== 1) {
        throw new Error("surface_registry_canonicalization_version_mismatch");
      }
      return 1;
    }
    const v = (protectedHeader as Record<string, unknown>).canon;
    if (typeof v !== "number" || !Number.isInteger(v)) {
      throw new Error("surface_registry_signature_invalid");
    }
    if (v !== SURFACE_REGISTRY_CANON_VERSION) {
      throw new Error("surface_registry_canonicalization_version_mismatch");
    }
    return v;
  })();

  // Strict determinism guard: stable key insertion order; no extra fields.
  const expectedProtectedB64 = protectedHeaderToDeterministicB64url({
    kid,
    canon,
    legacy: isLegacy
  });
  if (protectedB64url !== expectedProtectedB64) {
    throw new Error("surface_registry_signature_invalid");
  }

  return { kid, canon, legacy: isLegacy };
};

export const verifySurfaceRegistryBundle = async (input: {
  bundle: SurfaceRegistryBundle;
  publicKeyJwkBase64url: string;
  canonicalize?: (value: unknown) => string;
}): Promise<SurfaceRegistry> => {
  try {
    const { bundle } = input;
    const canonicalize = input.canonicalize ?? canonicalizeJson;

    // Validate version + strict protected header determinism BEFORE signature verification.
    parseAndValidateProtectedHeader(bundle.signature.protected);

    // Defensive: ensure the payload is exactly the canonical JSON of `bundle.registry`.
    const canonical = canonicalize(bundle.registry);
    const expectedPayload = Buffer.from(canonical, "utf8").toString("base64url");
    if (bundle.signature.payload !== expectedPayload) {
      throw new Error("surface_registry_integrity_failed");
    }

    const compact = `${bundle.signature.protected}.${bundle.signature.payload}.${bundle.signature.signature}`;
    const jwk = parsePublicJwkFromEnv(input.publicKeyJwkBase64url);
    const key = await importJWK(jwk as never, "EdDSA");

    const { payload } = await compactVerify(compact, key, { algorithms: ["EdDSA"] });
    const payloadText = new TextDecoder().decode(payload);
    if (payloadText !== canonical) {
      throw new Error("surface_registry_integrity_failed");
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === "surface_registry_canonicalization_version_mismatch") {
      throw new Error(msg);
    }
    throw new Error("surface_registry_integrity_failed");
  }

  return input.bundle.registry;
};

type SurfaceRegistryLogger = {
  warn: (event: string, meta?: Record<string, unknown>) => void;
};

// Public (non-secret) local dev key for signature verification when no env key is provided.
// This is ONLY used in non-production flows.
const DEV_FALLBACK_PUBLIC_JWK_B64URL =
  "eyJjcnYiOiJFZDI1NTE5IiwieCI6ImZtZXJOMk9uM2Rzck00OVhaS2hBQWVHT2VuaWM2SkpqaVhaTmhrQXphV3MiLCJrdHkiOiJPS1AiLCJhbGciOiJFZERTQSIsImtpZCI6InN1cmZhY2UtcmVnaXN0cnktc3NpLTEifQ";

let cachedRuntimeRegistry: {
  cacheKey: string;
  registry: SurfaceRegistry;
  mode: "bundle" | "unsigned";
} | null = null;

export const loadSurfaceRegistryForRuntime = async (input: {
  nodeEnv: string;
  bundlePath: string;
  registryPath: string;
  publicKeyJwkBase64url?: string;
  logger?: SurfaceRegistryLogger;
}): Promise<SurfaceRegistry> => {
  const production = input.nodeEnv === "production";
  const publicKeyJwkBase64url = String(input.publicKeyJwkBase64url ?? "").trim();
  const cacheKey = [
    production ? "prod" : "dev",
    input.bundlePath,
    input.registryPath,
    publicKeyJwkBase64url || "(missing)"
  ].join("|");
  if (cachedRuntimeRegistry?.cacheKey === cacheKey) {
    return cachedRuntimeRegistry.registry;
  }

  const warn = (event: string, meta?: Record<string, unknown>) => {
    if (input.logger?.warn) {
      input.logger.warn(event, meta);
      return;
    }
    console.warn(event, meta ? JSON.stringify(meta) : "");
  };

  if (production) {
    if (!publicKeyJwkBase64url) {
      throw new Error("surface_registry_integrity_failed");
    }
    try {
      const bundle = loadSurfaceRegistryBundleFromFile(input.bundlePath);
      const registry = await verifySurfaceRegistryBundle({
        bundle,
        publicKeyJwkBase64url
      });
      cachedRuntimeRegistry = { cacheKey, registry, mode: "bundle" };
      return registry;
    } catch {
      throw new Error("surface_registry_integrity_failed");
    }
  }

  // Non-production: prefer verified bundle when possible, but allow unsigned registry for dev.
  const keyForDev = publicKeyJwkBase64url || DEV_FALLBACK_PUBLIC_JWK_B64URL;
  if (existsSync(input.bundlePath)) {
    try {
      const bundle = loadSurfaceRegistryBundleFromFile(input.bundlePath);
      const registry = await verifySurfaceRegistryBundle({
        bundle,
        publicKeyJwkBase64url: keyForDev
      });
      cachedRuntimeRegistry = { cacheKey, registry, mode: "bundle" };
      return registry;
    } catch {
      warn("surface.registry.signature_invalid_dev_fallback", { env: input.nodeEnv });
      // fall through to unsigned
    }
  } else {
    warn("surface.registry.signature_missing_dev_fallback", { env: input.nodeEnv });
  }

  const registry = loadSurfaceRegistryFromFile(input.registryPath);
  cachedRuntimeRegistry = { cacheKey, registry, mode: "unsigned" };
  return registry;
};

const escapeRegex = (value: string) => value.replace(/[.+?^${}()|[\]\\]/g, "\\$&");

export const compileSurfacePathPattern = (pathPattern: string): RegExp => {
  let out = "";
  for (let i = 0; i < pathPattern.length; i += 1) {
    const ch = pathPattern[i]!;
    if (ch === "*") {
      out += ".*";
      continue;
    }
    if (ch === ":") {
      let j = i + 1;
      while (j < pathPattern.length) {
        const c = pathPattern[j]!;
        if (!/[A-Za-z0-9_]/.test(c)) break;
        j += 1;
      }
      if (j === i + 1) {
        out += escapeRegex(ch);
      } else {
        out += "[^/]+";
        i = j - 1;
      }
      continue;
    }
    out += escapeRegex(ch);
  }
  return new RegExp(`^${out}$`);
};

const specificityScore = (pathPattern: string) => {
  // Higher is more specific.
  let staticChars = 0;
  let wildcards = 0;
  let params = 0;
  for (let i = 0; i < pathPattern.length; i += 1) {
    const ch = pathPattern[i]!;
    if (ch === "*") {
      wildcards += 1;
      continue;
    }
    if (ch === ":") {
      params += 1;
      continue;
    }
    staticChars += 1;
  }
  return staticChars * 1000 - wildcards * 50 - params * 10;
};

export type CompiledSurfaceRoute = SurfaceRouteEntry & {
  re: RegExp;
  specificity: number;
};

export const compileSurfaceRoutesForService = (
  registry: SurfaceRegistry,
  serviceId: string
): CompiledSurfaceRoute[] => {
  const svc = registry.services.find((s) => s.id === serviceId);
  if (!svc) return [];
  const compiled = (svc.routes ?? []).map((r) => ({
    ...r,
    re: compileSurfacePathPattern(r.path),
    specificity: specificityScore(r.path)
  }));
  // Prefer the most specific match (lets exact routes override globs like `/v1/social/*`).
  compiled.sort((a, b) => b.specificity - a.specificity);
  return compiled;
};

export const matchSurfaceRoute = (
  compiled: CompiledSurfaceRoute[],
  input: { method: string; path: string }
): CompiledSurfaceRoute | null => {
  const method = input.method.toUpperCase();
  for (const r of compiled) {
    if (r.method !== method) continue;
    if (r.re.test(input.path)) return r;
  }
  return null;
};
