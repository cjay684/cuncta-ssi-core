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

const isBase64UrlSecret = (value: string) => /^[A-Za-z0-9_-]+$/.test(value) && value.length >= 43;

const isHexSecret = (value: string) => /^[a-fA-F0-9]+$/.test(value) && value.length >= 64;

const isSecretFormatValid = (value: string) => isBase64UrlSecret(value) || isHexSecret(value);

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.preprocess(toNumber(3001), z.number().int().min(1).max(65535)),
  DEV_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  BACKUP_RESTORE_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  SERVICE_BIND_ADDRESS: z.string().optional(),
  PUBLIC_SERVICE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  TRUST_PROXY: z.preprocess((value) => value === "true", z.boolean()).default(false),
  LOCAL_DEV: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).default("testnet"),
  ALLOW_MAINNET: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_OPERATOR_ID: z.string().optional(),
  HEDERA_OPERATOR_PRIVATE_KEY: z.string().optional(),
  HEDERA_OPERATOR_ID_DID: z.string().optional(),
  HEDERA_OPERATOR_PRIVATE_KEY_DID: z.string().optional(),
  ALLOW_LEGACY_OPERATOR_KEYS: z.preprocess((value) => value === "true", z.boolean()).default(false),
  HEDERA_DID_TOPIC_ID: z.string().optional(),
  DID_REQUEST_TTL_MS: z.preprocess(toNumber(5 * 60 * 1000), z.number().int().min(1000)),
  DID_VISIBILITY_TIMEOUT_MS: z.preprocess(toNumber(2 * 60 * 1000), z.number().int().min(1000)),
  DID_WAIT_FOR_VISIBILITY: z.preprocess((value) => value !== "false", z.boolean()).default(true),
  BODY_LIMIT_BYTES: z.preprocess(toNumber(64 * 1024), z.number().int().min(1024)),
  ALLOW_INSECURE_DEV_AUTH: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ALLOW_LEGACY_SERVICE_JWT_SECRET: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false),
  SERVICE_JWT_SECRET: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_DID: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_NEXT: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_FORMAT_STRICT: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return undefined;
    return value === "true";
  }, z.boolean().optional()),
  SERVICE_JWT_AUDIENCE: z.string().default("cuncta-internal"),
  SERVICE_JWT_AUDIENCE_DID: z.string().default("cuncta.service.did")
});

const parsed = envSchema.parse(process.env);
if (parsed.HEDERA_NETWORK === "mainnet" && !parsed.ALLOW_MAINNET) {
  throw new Error("mainnet_not_allowed");
}
if (parsed.NODE_ENV === "production" && parsed.ALLOW_LEGACY_SERVICE_JWT_SECRET) {
  throw new Error("legacy_service_jwt_not_allowed_in_production");
}
if (parsed.ALLOW_LEGACY_SERVICE_JWT_SECRET) {
  console.warn(
    "ALLOW_LEGACY_SERVICE_JWT_SECRET is enabled (dev/test migration aid only; disable before production)."
  );
}
const strictSecrets =
  parsed.NODE_ENV === "test"
    ? false
    : (parsed.SERVICE_JWT_SECRET_FORMAT_STRICT ?? parsed.NODE_ENV === "production");
const serviceSecrets = [
  { name: "SERVICE_JWT_SECRET", value: parsed.SERVICE_JWT_SECRET },
  { name: "SERVICE_JWT_SECRET_DID", value: parsed.SERVICE_JWT_SECRET_DID },
  { name: "SERVICE_JWT_SECRET_NEXT", value: parsed.SERVICE_JWT_SECRET_NEXT }
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
export const config = {
  ...parsed,
  SERVICE_BIND_ADDRESS: serviceBindAddress,
  SERVICE_JWT_SECRET_FORMAT_STRICT: strictSecrets
};
