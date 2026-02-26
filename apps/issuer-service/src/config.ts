import dotenv from "dotenv";
import path from "path";
import { z } from "zod";

dotenv.config({ path: path.resolve(process.cwd(), "../../.env") });

const toNumber = (fallback: number) => (value: unknown) => {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number(value);
  return Number.isNaN(parsed) ? fallback : parsed;
};

const emptyToUndefined = (value: unknown) => (value === "" ? undefined : value);

const clampNumber =
  (fallback: number, min: number, max: number) =>
  (value: unknown): number => {
    if (value === undefined || value === null || value === "") return fallback;
    const parsed = Number(value);
    if (Number.isNaN(parsed)) return fallback;
    return Math.max(min, Math.min(max, parsed));
  };

const toCsvList = (value: unknown) => {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((entry) => String(entry).trim()).filter(Boolean);
  return String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
};

const isBase64UrlSecret = (value: string) => /^[A-Za-z0-9_-]+$/.test(value) && value.length >= 43;

const isHexSecret = (value: string) => /^[a-fA-F0-9]+$/.test(value) && value.length >= 64;

const isSecretFormatValid = (value: string) => isBase64UrlSecret(value) || isHexSecret(value);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.preprocess(toNumber(3002), z.number().int().min(1).max(65535)),
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
  HEDERA_OPERATOR_ID: z.string().optional(),
  HEDERA_OPERATOR_PRIVATE_KEY: z.string().optional(),
  HEDERA_OPERATOR_ID_ANCHOR: z.string().optional(),
  HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR: z.string().optional(),
  ALLOW_LEGACY_OPERATOR_KEYS: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_ANCHOR_TOPIC_ID: z.string().optional(),
  DID_SERVICE_BASE_URL: z.string().url().default("http://localhost:3001"),
  ISSUER_BASE_URL: z.string().url(),
  ISSUER_DID: z.string().optional(),
  ISSUER_JWK: z.string().min(10).optional(),
  ISSUER_KEYS_BOOTSTRAP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ISSUER_KEYS_ALLOW_DB_PRIVATE: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  SDJWT_COMPAT_LEGACY_TYP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  STATUS_LIST_LENGTH: z.preprocess(toNumber(1024), z.number().int().min(1)),
  TOKEN_TTL_SECONDS: z.preprocess(toNumber(300), z.number().int().min(30)),
  OID4VCI_ACCESS_TOKEN_TTL_SECONDS: z.preprocess(toNumber(300), z.number().int().min(30)),
  OID4VCI_ACCESS_TOKEN_SECRET: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  OID4VCI_TOKEN_SIGNING_JWK: z.preprocess(emptyToUndefined, z.string().min(10).optional()),
  OID4VCI_TOKEN_SIGNING_BOOTSTRAP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  OID4VCI_PREAUTH_CODE_TTL_SECONDS: z.preprocess(toNumber(300), z.number().int().min(30).max(3600)),
  OID4VCI_C_NONCE_TTL_SECONDS: z.preprocess(toNumber(300), z.number().int().min(30).max(3600)),
  OID4VCI_OFFER_CHALLENGE_TTL_SECONDS: z.preprocess(toNumber(120), z.number().int().min(30).max(600)),
  OID4VCI_DID_RESOLVE_TIMEOUT_MS: z.preprocess(
    clampNumber(1500, 200, 10000),
    z.number().int().min(200).max(10000)
  ),
  OID4VCI_ENFORCE_DID_KEY_BINDING: z.preprocess((value) => value === "true", z.boolean()).optional(),
  ISSUER_BBS_SECRET_KEY_B64U: z.preprocess(emptyToUndefined, z.string().min(10).optional()),
  ISSUER_BBS_PUBLIC_KEY_B64U: z.preprocess(emptyToUndefined, z.string().min(10).optional()),
  // ZK tracks are optional and require explicit opt-in in production.
  ALLOW_EXPERIMENTAL_ZK: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  RATE_LIMIT_IP_TOKEN_PER_MIN: z.preprocess(toNumber(30), z.number().int().min(1)),
  RATE_LIMIT_IP_CREDENTIAL_PER_MIN: z.preprocess(toNumber(30), z.number().int().min(1)),
  ISSUER_ENABLE_OID4VCI: z.preprocess((value) => value === "true", z.boolean()).optional(),
  ANCHOR_OUTBOX_PROCESSING_TIMEOUT_MS: z.preprocess(
    clampNumber(120_000, 30_000, 600_000),
    z.number().int().min(30_000).max(600_000)
  ),
  ANCHOR_WORKER_POLL_MS: z.preprocess(
    clampNumber(2000, 250, 10_000),
    z.number().int().min(250).max(10_000)
  ),
  ANCHOR_TICK_TIMEOUT_MS: z.preprocess(
    clampNumber(120_000, 10_000, 600_000),
    z.number().int().min(10_000).max(600_000)
  ),
  AURA_WORKER_POLL_MS: z.preprocess(
    clampNumber(5000, 250, 30_000),
    z.number().int().min(250).max(30_000)
  ),
  ANCHOR_MAX_ATTEMPTS: z.preprocess(clampNumber(25, 3, 200), z.number().int().min(3).max(200)),
  OUTBOX_BATCH_SIZE: z.preprocess(clampNumber(25, 1, 200), z.number().int().min(1).max(200)),
  // Anchoring fee + payload discipline (2026-safe defaults, operator-tunable).
  ANCHOR_PUBLISH_MAX_FEE_TINYBARS: z.preprocess(
    clampNumber(100_000_000, 1_000_000, 5_000_000_000),
    z.number().int().min(1_000_000).max(5_000_000_000)
  ),
  ANCHOR_MESSAGE_MAX_BYTES: z.preprocess(
    clampNumber(1024, 256, 8192),
    z.number().int().min(256).max(8192)
  ),
  MIRROR_NODE_BASE_URL: z.preprocess(emptyToUndefined, z.string().url().optional()),
  ANCHOR_RECONCILIATION_ENABLED: z
    .preprocess((value) => value === "true", z.boolean())
    .optional(),
  ANCHOR_RECONCILE_TIMEOUT_MS: z.preprocess(
    clampNumber(3000, 500, 30_000),
    z.number().int().min(500).max(30_000)
  ),
  ANCHOR_RECONCILE_MAX_ATTEMPTS: z.preprocess(
    clampNumber(10, 1, 50),
    z.number().int().min(1).max(50)
  ),
  ANCHOR_RECONCILE_BATCH_SIZE: z.preprocess(
    clampNumber(5, 1, 50),
    z.number().int().min(1).max(50)
  ),
  ANCHOR_RECONCILER_POLL_MS: z.preprocess(
    clampNumber(60 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000),
    z.number().int().min(60 * 1000).max(24 * 60 * 60 * 1000)
  ),
  CLEANUP_WORKER_POLL_MS: z.preprocess(
    clampNumber(60 * 60 * 1000, 60 * 1000, 24 * 60 * 60 * 1000),
    z
      .number()
      .int()
      .min(60 * 1000)
      .max(24 * 60 * 60 * 1000)
  ),
  RETENTION_VERIFICATION_CHALLENGES_DAYS: z.preprocess(
    clampNumber(7, 1, 90),
    z.number().int().min(1).max(90)
  ),
  RETENTION_RATE_LIMIT_EVENTS_DAYS: z.preprocess(
    clampNumber(7, 1, 90),
    z.number().int().min(1).max(90)
  ),
  RETENTION_OBLIGATION_EVENTS_DAYS: z.preprocess(
    clampNumber(30, 1, 365),
    z.number().int().min(1).max(365)
  ),
  RETENTION_AURA_SIGNALS_DAYS: z.preprocess(
    // Aura signals are the most surveillance-sensitive store; keep short by default.
    clampNumber(30, 1, 365),
    z.number().int().min(1).max(365)
  ),
  RETENTION_AURA_STATE_DAYS: z.preprocess(
    clampNumber(180, 7, 730),
    z.number().int().min(7).max(730)
  ),
  RETENTION_AURA_ISSUANCE_QUEUE_DAYS: z.preprocess(
    clampNumber(30, 7, 365),
    z.number().int().min(7).max(365)
  ),
  RETENTION_AUDIT_LOGS_DAYS: z.preprocess(
    clampNumber(90, 7, 730),
    z.number().int().min(7).max(730)
  ),
  PRIVACY_CHALLENGE_TTL_SECONDS: z.preprocess(
    clampNumber(180, 30, 900),
    z.number().int().min(30).max(900)
  ),
  PRIVACY_TOKEN_TTL_SECONDS: z.preprocess(
    clampNumber(900, 60, 3600),
    z.number().int().min(60).max(3600)
  ),
  PRIVACY_ERASE_EPOCH_EXPECTED: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    const parsed = Number(value);
    return Number.isInteger(parsed) && parsed >= 0 ? parsed : undefined;
  }, z.number().int().min(0).optional()),
  BODY_LIMIT_BYTES: z.preprocess(toNumber(64 * 1024), z.number().int().min(1024)),
  PSEUDONYMIZER_PEPPER: z.string().optional(),
  PSEUDONYMIZER_ALLOW_LEGACY: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  ALLOW_INSECURE_DEV_AUTH: z.preprocess((value) => value === "true", z.boolean()).default(false),
  DATABASE_URL: z.string().default("postgres://cuncta:cuncta@localhost:5432/cuncta_ssi"),
  SERVICE_JWT_SECRET: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_ISSUER: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_NEXT: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  ALLOW_LEGACY_SERVICE_JWT_SECRET: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  SERVICE_JWT_SECRET_FORMAT_STRICT: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  SERVICE_JWT_AUDIENCE: z.string().default("cuncta-internal"),
  SERVICE_JWT_AUDIENCE_ISSUER: z.string().default("cuncta.service.issuer"),
  ISSUER_INTERNAL_ALLOWED_VCTS: z.preprocess(toCsvList, z.array(z.string()).default([])),
  POLICY_SIGNING_JWK: z.string().min(10).optional(),
  POLICY_SIGNING_BOOTSTRAP: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ANCHOR_AUTH_SECRET: z.string().min(16).optional(),
  STRICT_DB_ROLE: z.preprocess((value) => value === "true", z.boolean()).optional()
});

export const parseConfig = (env: NodeJS.ProcessEnv) => {
  const parsed = envSchema.parse(env);
  if (parsed.NODE_ENV === "production" && (!env.DATABASE_URL || String(env.DATABASE_URL).trim() === "")) {
    // Fail closed: production must be explicitly wired to its DB (no implicit local fallback).
    throw new Error("database_url_required_in_production");
  }
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
  if (parsed.NODE_ENV === "production" && parsed.ISSUER_KEYS_ALLOW_DB_PRIVATE) {
    throw new Error("issuer_db_private_keys_not_allowed_in_production");
  }
  if (parsed.ALLOW_LEGACY_SERVICE_JWT_SECRET) {
    console.warn(
      "ALLOW_LEGACY_SERVICE_JWT_SECRET is enabled (dev/test migration aid only; disable before production)."
    );
  }
  if (parsed.NODE_ENV === "production" && parsed.ENFORCE_HTTPS_INTERNAL) {
    const didUrl = new URL(parsed.DID_SERVICE_BASE_URL);
    if (didUrl.protocol !== "https:") {
      throw new Error("internal_url_https_required:DID_SERVICE_BASE_URL");
    }
  }
  const strictSecrets =
    parsed.NODE_ENV === "test"
      ? false
      : (parsed.SERVICE_JWT_SECRET_FORMAT_STRICT ?? parsed.NODE_ENV === "production");
  const serviceSecrets = [
    { name: "SERVICE_JWT_SECRET", value: parsed.SERVICE_JWT_SECRET },
    { name: "SERVICE_JWT_SECRET_ISSUER", value: parsed.SERVICE_JWT_SECRET_ISSUER },
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
  const mirrorBaseUrl =
    parsed.MIRROR_NODE_BASE_URL ??
    (parsed.HEDERA_NETWORK === "mainnet"
      ? "https://mainnet.mirrornode.hedera.com/api/v1"
      : parsed.HEDERA_NETWORK === "previewnet"
        ? "https://previewnet.mirrornode.hedera.com/api/v1"
        : "https://testnet.mirrornode.hedera.com/api/v1");
  const reconciliationEnabled = parsed.ANCHOR_RECONCILIATION_ENABLED ?? true;
  if (!reconciliationEnabled) {
    if (parsed.NODE_ENV === "production" && parsed.HEDERA_NETWORK === "mainnet") {
      throw new Error("anchor_reconciliation_required_on_mainnet_production");
    }
    console.warn(
      "ANCHOR_RECONCILIATION_ENABLED is disabled (not recommended; required on mainnet production)."
    );
  }
  const enableOid4vci = parsed.ISSUER_ENABLE_OID4VCI ?? true;
  if (parsed.NODE_ENV === "production" && enableOid4vci) {
    if (!parsed.OID4VCI_TOKEN_SIGNING_JWK) {
      throw new Error("oid4vci_token_signing_jwk_required_in_production");
    }
    if (parsed.OID4VCI_TOKEN_SIGNING_BOOTSTRAP) {
      throw new Error("oid4vci_token_signing_bootstrap_not_allowed_in_production");
    }
  }
  const allowExperimentalZk = parsed.ALLOW_EXPERIMENTAL_ZK ?? parsed.NODE_ENV !== "production";
  if (parsed.NODE_ENV === "production" && allowExperimentalZk) {
    console.warn(
      "[EXPERIMENTAL] ALLOW_EXPERIMENTAL_ZK=true — ZK/DI features enabled in production; ensure ceremony-grade artifacts."
    );
  }
  return {
    ...parsed,
    ALLOW_EXPERIMENTAL_ZK: allowExperimentalZk,
    AUTO_MIGRATE: autoMigrate,
    STRICT_DB_ROLE: strictDbRole,
    PSEUDONYMIZER_ALLOW_LEGACY: allowLegacy,
    SERVICE_BIND_ADDRESS: serviceBindAddress,
    SERVICE_JWT_SECRET_FORMAT_STRICT: strictSecrets,
    MIRROR_NODE_BASE_URL: mirrorBaseUrl,
    ANCHOR_RECONCILIATION_ENABLED: reconciliationEnabled,
    ISSUER_ENABLE_OID4VCI: enableOid4vci,
    OID4VCI_ENFORCE_DID_KEY_BINDING:
      parsed.OID4VCI_ENFORCE_DID_KEY_BINDING ?? parsed.NODE_ENV === "production"
  };
};
export const config = parseConfig(process.env);
