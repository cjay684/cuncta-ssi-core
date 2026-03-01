import dotenv from "dotenv";
import path from "path";
import { z } from "zod";

dotenv.config({
  path: path.resolve(process.cwd(), "../../.env")
});

const toNumber = (fallback: number) => (value: unknown) => {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const emptyToUndefined = (value: unknown) => (value === "" ? undefined : value);

const clampNumber = (fallback: number, min: number, max: number) => (value: unknown) => {
  const parsed = toNumber(fallback)(value);
  return Math.max(min, Math.min(max, parsed));
};

const isBase64UrlSecret = (value: string) => /^[A-Za-z0-9_-]+$/.test(value) && value.length >= 43;

const isHexSecret = (value: string) => /^[a-fA-F0-9]+$/.test(value) && value.length >= 64;

const isSecretFormatValid = (value: string) => isBase64UrlSecret(value) || isHexSecret(value);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.preprocess(toNumber(3003), z.number().int().min(1).max(65535)),
  DEV_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  BACKUP_RESTORE_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  SERVICE_BIND_ADDRESS: z.string().optional(),
  PUBLIC_SERVICE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  TRUST_PROXY: z.preprocess((value) => value === "true", z.boolean()).default(false),
  AUTO_MIGRATE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  ENFORCE_HTTPS_INTERNAL: z.preprocess((value) => value === "true", z.boolean()).default(false),
  LOCAL_DEV: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).default("testnet"),
  ALLOW_MAINNET: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  POLICY_SERVICE_BASE_URL: z.string().url().default("http://localhost:3004"),
  DID_SERVICE_BASE_URL: z.preprocess(emptyToUndefined, z.string().url().optional()),
  // Data-driven compliance profile selection (UK vs EU vs default).
  COMPLIANCE_PROFILE_DEFAULT: z.string().default("default"),
  // JSON map from verifier origin to profile_id, e.g. {"https://rp.example":"uk"}.
  COMPLIANCE_PROFILE_ORIGIN_MAP_JSON: z.preprocess(emptyToUndefined, z.string().min(2).optional()),
  ISSUER_JWKS: z.preprocess((value) => (value ? value : undefined), z.string().min(10).optional()),
  VERIFIER_AUDIENCE: z.string().min(3).optional(),
  SDJWT_COMPAT_LEGACY_TYP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ALLOW_INSECURE_DEV_AUTH: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ALLOW_LEGACY_SERVICE_JWT_SECRET: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  PSEUDONYMIZER_PEPPER: z.string().optional(),
  PSEUDONYMIZER_ALLOW_LEGACY: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  STATUS_LIST_FETCH_TIMEOUT_MS: z.preprocess(
    clampNumber(2500, 500, 10000),
    z.number().int().min(500).max(10000)
  ),
  STATUS_LIST_STRICT_MODE: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  STATUS_LIST_CACHE_TTL_SECONDS: z.preprocess(
    clampNumber(10, 1, 60),
    z.number().int().min(1).max(60)
  ),
  STATUS_LIST_CACHE_MAX_ENTRIES: z.preprocess(
    clampNumber(64, 8, 1024),
    z.number().int().min(8).max(1024)
  ),
  ENFORCE_DID_KEY_BINDING: z.preprocess((value) => value === "true", z.boolean()).optional(),
  DID_RESOLVE_TIMEOUT_MS: z.preprocess(
    clampNumber(1500, 200, 10000),
    z.number().int().min(200).max(10000)
  ),
  DID_RESOLVE_CACHE_TTL_SECONDS: z.preprocess(
    clampNumber(300, 1, 86400),
    z.number().int().min(1).max(86400)
  ),
  DID_RESOLVE_CACHE_MAX_ENTRIES: z.preprocess(
    clampNumber(256, 8, 4096),
    z.number().int().min(8).max(4096)
  ),
  ENFORCE_ORIGIN_AUDIENCE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  BREAK_GLASS_DISABLE_STRICT: z.preprocess((value) => value === "true", z.boolean()).default(false),
  VERIFIER_SIGN_OID4VP_REQUEST: z
    .preprocess((value) => value !== "false", z.boolean())
    .default(true),
  VERIFIER_SIGNING_JWK: z.preprocess(emptyToUndefined, z.string().min(10).optional()),
  VERIFIER_SIGNING_BOOTSTRAP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  VERIFIER_ENABLE_OID4VP: z.preprocess((value) => value === "true", z.boolean()).optional(),
  VERIFY_MAX_PRESENTATION_BYTES: z.preprocess(
    clampNumber(65536, 4096, 262144),
    z.number().int().min(4096).max(262144)
  ),
  VERIFY_MAX_NONCE_CHARS: z.preprocess(
    clampNumber(256, 32, 2048),
    z.number().int().min(32).max(2048)
  ),
  VERIFY_MAX_AUDIENCE_CHARS: z.preprocess(
    clampNumber(256, 32, 2048),
    z.number().int().min(32).max(2048)
  ),
  VERIFY_MAX_DISCLOSURES: z.preprocess(
    clampNumber(100, 10, 1000),
    z.number().int().min(10).max(1000)
  ),
  POLICY_SIGNING_JWK: z.string().min(10).optional(),
  POLICY_VERSION_FLOOR_ENFORCED: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value !== "false";
  }, z.boolean().optional()),
  SERVICE_JWT_SECRET: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_VERIFIER: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_NEXT: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_AUDIENCE: z.string().default("cuncta-internal"),
  SERVICE_JWT_AUDIENCE_VERIFIER: z.string().default("cuncta.service.verifier"),
  SERVICE_JWT_SECRET_FORMAT_STRICT: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  ANCHOR_AUTH_SECRET: z.string().min(16).optional(),
  DATABASE_URL: z.string().default("postgres://cuncta:cuncta@localhost:5432/cuncta_ssi"),
  STRICT_DB_ROLE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  // ZK tracks are optional and require explicit opt-in in production.
  ALLOW_EXPERIMENTAL_ZK: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  VERIFIER_ZK_MAX_DAY_DRIFT_DAYS: z.preprocess(clampNumber(1, 0, 7), z.number().int().min(0).max(7))
});

const parsed = envSchema.parse(process.env);
if (parsed.HEDERA_NETWORK === "mainnet" && !parsed.ALLOW_MAINNET) {
  throw new Error("mainnet_not_allowed");
}
if (
  parsed.NODE_ENV === "production" &&
  parsed.HEDERA_NETWORK === "mainnet" &&
  parsed.VERIFIER_SIGNING_BOOTSTRAP
) {
  throw new Error("verifier_signing_bootstrap_forbidden_on_mainnet_production");
}
if (
  parsed.VERIFIER_SIGN_OID4VP_REQUEST &&
  parsed.NODE_ENV === "production" &&
  !parsed.VERIFIER_SIGNING_JWK
) {
  throw new Error("verifier_signing_jwk_required_in_production");
}
if (parsed.BREAK_GLASS_DISABLE_STRICT && parsed.NODE_ENV === "production") {
  throw new Error("break_glass_forbidden_in_production");
}
if (parsed.BREAK_GLASS_DISABLE_STRICT) {
  console.warn(
    "[BREAK_GLASS] BREAK_GLASS_DISABLE_STRICT=true — strict posture disabled. " +
      "Never use on mainnet or in production."
  );
}
const autoMigrate = parsed.AUTO_MIGRATE ?? parsed.NODE_ENV !== "production";
if (parsed.NODE_ENV === "production" && autoMigrate) {
  throw new Error("auto_migrate_not_allowed_in_production");
}
const strictDbRole = parsed.STRICT_DB_ROLE ?? parsed.NODE_ENV === "production";
if (parsed.NODE_ENV === "production" && !strictDbRole) {
  throw new Error("strict_db_role_required_in_production");
}
if (parsed.NODE_ENV === "production" && parsed.ALLOW_LEGACY_SERVICE_JWT_SECRET) {
  throw new Error("legacy_service_jwt_not_allowed_in_production");
}
if (parsed.ALLOW_LEGACY_SERVICE_JWT_SECRET) {
  console.warn(
    "ALLOW_LEGACY_SERVICE_JWT_SECRET is enabled (dev/test migration aid only; disable before production)."
  );
}
if (parsed.NODE_ENV === "production" && parsed.ENFORCE_HTTPS_INTERNAL) {
  const issuerUrl = new URL(parsed.ISSUER_SERVICE_BASE_URL);
  const policyUrl = new URL(parsed.POLICY_SERVICE_BASE_URL);
  if (issuerUrl.protocol !== "https:") {
    throw new Error("internal_url_https_required:ISSUER_SERVICE_BASE_URL");
  }
  if (policyUrl.protocol !== "https:") {
    throw new Error("internal_url_https_required:POLICY_SERVICE_BASE_URL");
  }
  if (parsed.DID_SERVICE_BASE_URL) {
    const didUrl = new URL(parsed.DID_SERVICE_BASE_URL);
    if (didUrl.protocol !== "https:") {
      throw new Error("internal_url_https_required:DID_SERVICE_BASE_URL");
    }
  }
}
const strictSecrets =
  parsed.NODE_ENV === "test"
    ? false
    : (parsed.SERVICE_JWT_SECRET_FORMAT_STRICT ?? parsed.NODE_ENV === "production");
const serviceSecrets = [
  { name: "SERVICE_JWT_SECRET", value: parsed.SERVICE_JWT_SECRET },
  { name: "SERVICE_JWT_SECRET_VERIFIER", value: parsed.SERVICE_JWT_SECRET_VERIFIER },
  { name: "SERVICE_JWT_SECRET_NEXT", value: parsed.SERVICE_JWT_SECRET_NEXT }
];

const allowExperimentalZk = parsed.ALLOW_EXPERIMENTAL_ZK ?? parsed.NODE_ENV !== "production";
if (parsed.NODE_ENV === "production" && allowExperimentalZk) {
  console.warn(
    "[EXPERIMENTAL] ALLOW_EXPERIMENTAL_ZK=true — ZK/DI features enabled in production; ensure ceremony-grade artifacts."
  );
}
if (strictSecrets) {
  for (const secret of serviceSecrets) {
    if (secret.value && !isSecretFormatValid(secret.value)) {
      throw new Error(`service_jwt_secret_format_invalid:${secret.name}`);
    }
  }
}
const allowLegacy = parsed.PSEUDONYMIZER_ALLOW_LEGACY ?? parsed.NODE_ENV !== "production";
const serviceBindAddress =
  parsed.SERVICE_BIND_ADDRESS ?? (parsed.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0");
export const config = {
  ...parsed,
  ALLOW_EXPERIMENTAL_ZK: allowExperimentalZk,
  AUTO_MIGRATE: autoMigrate,
  STRICT_DB_ROLE: strictDbRole,
  PSEUDONYMIZER_ALLOW_LEGACY: allowLegacy,
  SERVICE_BIND_ADDRESS: serviceBindAddress,
  SERVICE_JWT_SECRET_FORMAT_STRICT: strictSecrets,
  POLICY_VERSION_FLOOR_ENFORCED:
    parsed.POLICY_VERSION_FLOOR_ENFORCED ?? parsed.NODE_ENV === "production",
  STATUS_LIST_STRICT_MODE: parsed.STATUS_LIST_STRICT_MODE ?? parsed.NODE_ENV === "production",
  DID_SERVICE_BASE_URL: parsed.DID_SERVICE_BASE_URL ?? "http://localhost:3001",
  ENFORCE_DID_KEY_BINDING: parsed.BREAK_GLASS_DISABLE_STRICT
    ? false
    : (parsed.ENFORCE_DID_KEY_BINDING ?? parsed.NODE_ENV === "production"),
  BREAK_GLASS_DISABLE_STRICT: parsed.BREAK_GLASS_DISABLE_STRICT ?? false,
  ENFORCE_ORIGIN_AUDIENCE: parsed.BREAK_GLASS_DISABLE_STRICT
    ? false
    : (parsed.ENFORCE_ORIGIN_AUDIENCE ?? true),
  VERIFIER_SIGN_OID4VP_REQUEST: parsed.VERIFIER_SIGN_OID4VP_REQUEST ?? true,
  VERIFIER_ENABLE_OID4VP: parsed.VERIFIER_ENABLE_OID4VP ?? true
};
