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
  STATUS_LIST_CACHE_TTL_SECONDS: z.preprocess(
    clampNumber(10, 1, 60),
    z.number().int().min(1).max(60)
  ),
  STATUS_LIST_CACHE_MAX_ENTRIES: z.preprocess(
    clampNumber(64, 8, 1024),
    z.number().int().min(8).max(1024)
  ),
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
  STRICT_DB_ROLE: z.preprocess((value) => value === "true", z.boolean()).optional()
});

const parsed = envSchema.parse(process.env);
if (parsed.HEDERA_NETWORK === "mainnet" && !parsed.ALLOW_MAINNET) {
  throw new Error("mainnet_not_allowed");
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
  AUTO_MIGRATE: autoMigrate,
  STRICT_DB_ROLE: strictDbRole,
  PSEUDONYMIZER_ALLOW_LEGACY: allowLegacy,
  SERVICE_BIND_ADDRESS: serviceBindAddress,
  SERVICE_JWT_SECRET_FORMAT_STRICT: strictSecrets,
  POLICY_VERSION_FLOOR_ENFORCED:
    parsed.POLICY_VERSION_FLOOR_ENFORCED ?? parsed.NODE_ENV === "production"
};
