import dotenv from "dotenv";
import path from "path";
import net from "node:net";
import { z } from "zod";
import { defaultFeeBudgets, parseFeeBudgetsJson } from "@cuncta/hedera";

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

const toCsvList = (value: unknown) => {
  if (!value) return [];
  if (Array.isArray(value)) return value.map((entry) => String(entry).trim()).filter(Boolean);
  return String(value)
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
};
const isHederaAccountId = (value: string) => /^0\.0\.\d+$/.test(value);

const isBase64UrlSecret = (value: string) => /^[A-Za-z0-9_-]+$/.test(value) && value.length >= 43;

const isHexSecret = (value: string) => /^[a-fA-F0-9]+$/.test(value) && value.length >= 64;

const isSecretFormatValid = (value: string) => isBase64UrlSecret(value) || isHexSecret(value);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.preprocess(toNumber(3010), z.number().int().min(1).max(65535)),
  DEV_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  BACKUP_RESTORE_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  SERVICE_BIND_ADDRESS: z.string().optional(),
  PUBLIC_SERVICE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  TRUST_PROXY: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ENFORCE_HTTPS_INTERNAL: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).default("testnet"),
  ALLOW_MAINNET: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_DID_TOPIC_ID: z.string().optional(),
  DID_SERVICE_BASE_URL: z.string().url(),
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  VERIFIER_SERVICE_BASE_URL: z.string().url().optional(),
  POLICY_SERVICE_BASE_URL: z.string().url().optional(),
  APP_GATEWAY_PUBLIC_BASE_URL: z.string().url().optional(),
  GATEWAY_SIGN_OID4VP_REQUEST: z.preprocess((v) => v !== "false", z.boolean()).default(true),
  BREAK_GLASS_DISABLE_STRICT: z.preprocess((v) => v === "true", z.boolean()).default(false),
  SERVICE_JWT_SECRET: z.string().min(32),
  SERVICE_JWT_SECRET_DID: z.string().min(32).optional(),
  SERVICE_JWT_SECRET_ISSUER: z.string().min(32).optional(),
  SERVICE_JWT_SECRET_VERIFIER: z.string().min(32).optional(),
  ALLOW_LEGACY_SERVICE_JWT_SECRET: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  SERVICE_JWT_SECRET_FORMAT_STRICT: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  SERVICE_JWT_AUDIENCE: z.string().default("cuncta-internal"),
  SERVICE_JWT_AUDIENCE_DID: z.string().default("cuncta.service.did"),
  SERVICE_JWT_AUDIENCE_ISSUER: z.string().default("cuncta.service.issuer"),
  SERVICE_JWT_AUDIENCE_VERIFIER: z.string().default("cuncta.service.verifier"),
  SERVICE_JWT_TTL_SECONDS: z.preprocess(toNumber(120), z.number().int().min(30).max(3600)),
  GATEWAY_VERIFY_DEBUG_REASONS: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  CONTRACT_E2E_ENABLED: z.preprocess((value) => value === "true", z.boolean()).default(false),
  CONTRACT_E2E_ADMIN_TOKEN: z.string().min(16).optional(),
  CONTRACT_E2E_IP_ALLOWLIST: z.preprocess(toCsvList, z.array(z.string()).default([])),
  ALLOW_SELF_FUNDED_ONBOARDING: z
    .preprocess((value) => value !== "false", z.boolean())
    .default(true),
  USER_PAYS_HANDOFF_SECRET: z.preprocess(
    (value) => (value ? value : undefined),
    z.string().min(32).optional()
  ),
  PSEUDONYMIZER_PEPPER: z.string().min(10),
  // ZK tracks are optional and require explicit opt-in in production.
  ALLOW_EXPERIMENTAL_ZK: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  BODY_LIMIT_BYTES: z.preprocess(toNumber(64 * 1024), z.number().int().min(1024)),
  RATE_LIMIT_IP_DEFAULT_PER_MIN: z.preprocess(toNumber(120), z.number().int().min(1)),
  RATE_LIMIT_IP_DID_REQUEST_PER_MIN: z.preprocess(toNumber(10), z.number().int().min(1)),
  RATE_LIMIT_IP_DID_SUBMIT_PER_MIN: z.preprocess(toNumber(5), z.number().int().min(1)),
  RATE_LIMIT_IP_ISSUE_PER_MIN: z.preprocess(toNumber(10), z.number().int().min(1)),
  RATE_LIMIT_IP_VERIFY_PER_MIN: z.preprocess(toNumber(60), z.number().int().min(1)),
  RATE_LIMIT_IP_COMMAND_PER_MIN: z.preprocess(toNumber(60), z.number().int().min(1)),
  RATE_LIMIT_DEVICE_REQUIREMENTS_PER_MIN: z.preprocess(toNumber(60), z.number().int().min(1)),
  RATE_LIMIT_DEVICE_DID_PER_DAY: z.preprocess(toNumber(3), z.number().int().min(1)),
  RATE_LIMIT_DEVICE_ISSUE_PER_MIN: z.preprocess(toNumber(10), z.number().int().min(1)),
  USER_PAYS_REQUEST_TTL_SECONDS: z.preprocess(toNumber(300), z.number().int().min(30).max(3600)),
  USER_PAYS_MAX_TX_BYTES: z.preprocess(toNumber(32 * 1024), z.number().int().min(1024)),
  USER_PAYS_MAX_FEE_TINYBARS: z.preprocess(
    toNumber(50_000_000),
    z.number().int().min(1).max(1_000_000_000)
  ),
  // Data-driven per-transaction budgets (defaults to the legacy USER_PAYS_* caps).
  USER_PAYS_FEE_BUDGETS_JSON: z.string().default(""),
  GATEWAY_ALLOWED_VCTS: z.preprocess(toCsvList, z.array(z.string()).default([])),
  GATEWAY_REQUIREMENTS_ALLOWED_ACTIONS: z.preprocess(toCsvList, z.array(z.string()).default([])),
  REQUIRE_DEVICE_ID_FOR_REQUIREMENTS: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  DATABASE_URL: z.string().default("postgres://cuncta:cuncta@localhost:5432/cuncta_ssi"),
  REALTIME_ALLOW_QUERY_TOKEN: z.preprocess((value) => value !== "false", z.boolean()).default(true),
  VERIFIER_PROXY_TIMEOUT_MS: z.preprocess(toNumber(2500), z.number().int().min(250).max(30_000)),
  COMMAND_PLANNER_REQUIREMENTS_TIMEOUT_MS: z.preprocess(
    toNumber(1500),
    z.number().int().min(250).max(30_000)
  ),
  COMMAND_FEE_SCHEDULE_JSON: z.string().default(""),
  PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET: z.string().default(""),
  PAYMENTS_RECEIVER_ACCOUNT_ID_MAINNET: z.string().default(""),
  HEDERA_TX_MEMO_MAX_BYTES: z.preprocess(toNumber(100), z.number().int().min(16).max(256)),
  REALTIME_WS_POLL_MS: z.preprocess(toNumber(1000), z.number().int().min(250).max(10_000)),
  STRICT_DB_ROLE: z.preprocess((value) => value === "true", z.boolean()).optional()
});

if (process.env.ALLOW_SPONSORED_ONBOARDING === "true") {
  throw new Error(
    "ALLOW_SPONSORED_ONBOARDING is not supported. CUNCTA supports self-funded onboarding only."
  );
}
const parsed = envSchema.parse(process.env);
const isValidIpOrCidr = (entry: string) => {
  const trimmed = entry.trim();
  if (!trimmed) return false;
  const [ipPart, prefixPart] = trimmed.split("/");
  if (!prefixPart) {
    return net.isIP(ipPart) !== 0;
  }
  const prefix = Number(prefixPart);
  const ipType = net.isIP(ipPart);
  if (!Number.isInteger(prefix)) return false;
  if (ipType === 4) return prefix >= 0 && prefix <= 32;
  if (ipType === 6) return prefix >= 0 && prefix <= 128;
  return false;
};
for (const entry of parsed.CONTRACT_E2E_IP_ALLOWLIST) {
  if (!isValidIpOrCidr(entry)) {
    throw new Error(`contract_e2e_ip_allowlist_invalid:${entry}`);
  }
}
if (parsed.CONTRACT_E2E_ENABLED) {
  if (parsed.NODE_ENV === "production") {
    throw new Error("contract_e2e_disabled_in_production");
  }
  if (!parsed.CONTRACT_E2E_ADMIN_TOKEN) {
    throw new Error("contract_e2e_admin_token_required");
  }
}
if (parsed.ALLOW_SELF_FUNDED_ONBOARDING && !parsed.USER_PAYS_HANDOFF_SECRET) {
  throw new Error("user_pays_handoff_secret_required");
}
if (parsed.HEDERA_NETWORK === "mainnet" && !parsed.ALLOW_MAINNET) {
  throw new Error("mainnet_not_allowed");
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
if (
  parsed.PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET &&
  !isHederaAccountId(parsed.PAYMENTS_RECEIVER_ACCOUNT_ID_TESTNET)
) {
  throw new Error("payments_receiver_account_id_testnet_invalid");
}
if (
  parsed.PAYMENTS_RECEIVER_ACCOUNT_ID_MAINNET &&
  !isHederaAccountId(parsed.PAYMENTS_RECEIVER_ACCOUNT_ID_MAINNET)
) {
  throw new Error("payments_receiver_account_id_mainnet_invalid");
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
  const requiredInternalUrls = [
    ["DID_SERVICE_BASE_URL", parsed.DID_SERVICE_BASE_URL],
    ["ISSUER_SERVICE_BASE_URL", parsed.ISSUER_SERVICE_BASE_URL]
  ];
  if (parsed.VERIFIER_SERVICE_BASE_URL) {
    requiredInternalUrls.push(["VERIFIER_SERVICE_BASE_URL", parsed.VERIFIER_SERVICE_BASE_URL]);
  }
  if (parsed.POLICY_SERVICE_BASE_URL) {
    requiredInternalUrls.push(["POLICY_SERVICE_BASE_URL", parsed.POLICY_SERVICE_BASE_URL]);
  }
  for (const [name, value] of requiredInternalUrls) {
    if (new URL(value).protocol !== "https:") {
      throw new Error(`internal_url_https_required:${name}`);
    }
  }
}
const strictSecrets = parsed.SERVICE_JWT_SECRET_FORMAT_STRICT ?? parsed.NODE_ENV === "production";
const serviceSecrets = [
  { name: "SERVICE_JWT_SECRET", value: parsed.SERVICE_JWT_SECRET },
  { name: "SERVICE_JWT_SECRET_DID", value: parsed.SERVICE_JWT_SECRET_DID },
  { name: "SERVICE_JWT_SECRET_ISSUER", value: parsed.SERVICE_JWT_SECRET_ISSUER },
  { name: "SERVICE_JWT_SECRET_VERIFIER", value: parsed.SERVICE_JWT_SECRET_VERIFIER },
];
if (strictSecrets) {
  for (const secret of serviceSecrets) {
    if (secret.value && !isSecretFormatValid(secret.value)) {
      throw new Error(`service_jwt_secret_format_invalid:${secret.name}`);
    }
  }
}
const serviceBindAddress =
  parsed.SERVICE_BIND_ADDRESS ?? (parsed.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0");
const gatewayPublicBaseUrl =
  parsed.APP_GATEWAY_PUBLIC_BASE_URL ??
  (parsed.NODE_ENV !== "production" ? "http://localhost:3010" : undefined);
const allowExperimentalZk = parsed.ALLOW_EXPERIMENTAL_ZK ?? parsed.NODE_ENV !== "production";
if (parsed.NODE_ENV === "production" && allowExperimentalZk) {
  console.warn(
    "[EXPERIMENTAL] ALLOW_EXPERIMENTAL_ZK=true — ZK/DI features enabled in production; ensure ceremony-grade artifacts."
  );
}
const userPaysFeeBudgets = parseFeeBudgetsJson(
  parsed.USER_PAYS_FEE_BUDGETS_JSON,
  defaultFeeBudgets({
    userPaysMaxFeeTinybars: parsed.USER_PAYS_MAX_FEE_TINYBARS,
    userPaysMaxTxBytes: parsed.USER_PAYS_MAX_TX_BYTES
  })
);
export const config = {
  ...parsed,
  ALLOW_EXPERIMENTAL_ZK: allowExperimentalZk,
  STRICT_DB_ROLE: strictDbRole,
  SERVICE_BIND_ADDRESS: serviceBindAddress,
  SERVICE_JWT_SECRET_FORMAT_STRICT: strictSecrets,
  APP_GATEWAY_PUBLIC_BASE_URL: gatewayPublicBaseUrl,
  USER_PAYS_FEE_BUDGETS: userPaysFeeBudgets,
  BREAK_GLASS_DISABLE_STRICT: parsed.BREAK_GLASS_DISABLE_STRICT ?? false,
  GATEWAY_SIGN_OID4VP_REQUEST: parsed.BREAK_GLASS_DISABLE_STRICT
    ? false
    : (parsed.GATEWAY_SIGN_OID4VP_REQUEST ?? true)
};
