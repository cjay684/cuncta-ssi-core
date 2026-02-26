import dotenv from "dotenv";
import path from "path";
import { z } from "zod";

dotenv.config({ path: path.resolve(process.cwd(), "../../.env") });

const toNumber = (fallback: number) => (value: unknown) => {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const emptyToUndefined = (value: unknown) => (value === "" ? undefined : value);

const isBase64UrlSecret = (value: string) => /^[A-Za-z0-9_-]+$/.test(value) && value.length >= 43;

const isHexSecret = (value: string) => /^[a-fA-F0-9]+$/.test(value) && value.length >= 64;

const isSecretFormatValid = (value: string) => isBase64UrlSecret(value) || isHexSecret(value);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.preprocess(toNumber(3004), z.number().int().min(1).max(65535)),
  DEV_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  BACKUP_RESTORE_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  SERVICE_BIND_ADDRESS: z.string().optional(),
  PUBLIC_SERVICE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  TRUST_PROXY: z.preprocess((value) => value === "true", z.boolean()).default(false),
  AUTO_MIGRATE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  ENFORCE_HTTPS_INTERNAL: z.preprocess((value) => value === "true", z.boolean()).default(false),
  BODY_LIMIT_BYTES: z.preprocess(toNumber(64 * 1024), z.number().int().min(1024)),
  HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).default("testnet"),
  ALLOW_MAINNET: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_OPERATOR_ID: z.string().optional(),
  HEDERA_OPERATOR_PRIVATE_KEY: z.string().optional(),
  DATABASE_URL: z.string().default("postgres://cuncta:cuncta@localhost:5432/cuncta_ssi"),
  CHALLENGE_TTL_SECONDS: z.preprocess(toNumber(180), z.number().int().min(30).max(900)),
  // Data-driven compliance profile selection (UK vs EU vs default).
  COMPLIANCE_PROFILE_DEFAULT: z.string().default("default"),
  // JSON map from verifier origin to profile_id, e.g. {"https://rp.example":"uk"}.
  COMPLIANCE_PROFILE_ORIGIN_MAP_JSON: z.preprocess(
    emptyToUndefined,
    z.string().min(2).optional()
  ),
  POLICY_SIGNING_JWK: z.string().min(10).optional(),
  POLICY_SIGNING_BOOTSTRAP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ANCHOR_AUTH_SECRET: z.string().min(16).optional(),
  POLICY_VERSION_FLOOR_ENFORCED: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value !== "false";
  }, z.boolean().optional()),
  SERVICE_JWT_SECRET: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_POLICY: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_NEXT: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  ALLOW_LEGACY_SERVICE_JWT_SECRET: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  SERVICE_JWT_SECRET_FORMAT_STRICT: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  SERVICE_JWT_AUDIENCE: z.string().default("cuncta-internal"),
  SERVICE_JWT_AUDIENCE_POLICY: z.string().default("cuncta.service.policy"),
  STRICT_DB_ROLE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  ALLOW_EXPERIMENTAL_ZK: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional())
});

const parsed = envSchema.parse(process.env);
if (parsed.HEDERA_NETWORK === "mainnet" && !parsed.ALLOW_MAINNET) {
  throw new Error("mainnet_not_allowed");
}
if (parsed.NODE_ENV === "production" && parsed.HEDERA_NETWORK === "mainnet" && parsed.POLICY_SIGNING_BOOTSTRAP) {
  throw new Error("policy_signing_bootstrap_forbidden_on_mainnet_production");
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
const allowExperimentalZk = parsed.ALLOW_EXPERIMENTAL_ZK ?? parsed.NODE_ENV !== "production";
if (parsed.NODE_ENV === "production" && allowExperimentalZk) {
  console.warn(
    "[EXPERIMENTAL] ALLOW_EXPERIMENTAL_ZK=true — ZK features enabled in production; ensure registry statements are curated."
  );
}
const serviceBindAddress =
  parsed.SERVICE_BIND_ADDRESS ?? (parsed.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0");
const strictSecrets = parsed.SERVICE_JWT_SECRET_FORMAT_STRICT ?? parsed.NODE_ENV === "production";
const serviceSecrets = [
  { name: "SERVICE_JWT_SECRET", value: parsed.SERVICE_JWT_SECRET },
  { name: "SERVICE_JWT_SECRET_POLICY", value: parsed.SERVICE_JWT_SECRET_POLICY },
  { name: "SERVICE_JWT_SECRET_NEXT", value: parsed.SERVICE_JWT_SECRET_NEXT }
];
if (strictSecrets) {
  for (const secret of serviceSecrets) {
    if (secret.value && !isSecretFormatValid(secret.value)) {
      throw new Error(`service_jwt_secret_format_invalid:${secret.name}`);
    }
  }
}
export const config = {
  ...parsed,
  AUTO_MIGRATE: autoMigrate,
  STRICT_DB_ROLE: strictDbRole,
  SERVICE_BIND_ADDRESS: serviceBindAddress,
  SERVICE_JWT_SECRET_FORMAT_STRICT: strictSecrets,
  ALLOW_EXPERIMENTAL_ZK: allowExperimentalZk,
  POLICY_VERSION_FLOOR_ENFORCED: parsed.POLICY_VERSION_FLOOR_ENFORCED ?? parsed.NODE_ENV === "production"
};
