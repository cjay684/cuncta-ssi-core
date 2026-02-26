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

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.preprocess(toNumber(3005), z.number().int().min(1).max(65535)),
  DEV_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  AUTO_MIGRATE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  BACKUP_RESTORE_MODE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  STRICT_DB_ROLE: z.preprocess((value) => value === "true", z.boolean()).optional(),
  TRUST_PROXY: z.preprocess((value) => value === "true", z.boolean()).default(false),
  SERVICE_BIND_ADDRESS: z.string().optional(),
  PUBLIC_SERVICE: z.preprocess((value) => value === "true", z.boolean()).default(false),
  BODY_LIMIT_BYTES: z.preprocess(toNumber(64 * 1024), z.number().int().min(1024)),
  DATABASE_URL: z.string().default("postgres://cuncta:cuncta@localhost:5432/cuncta_ssi"),
  PSEUDONYMIZER_PEPPER: z.string().min(10),
  APP_GATEWAY_BASE_URL: z.string().url(),
  ISSUER_SERVICE_BASE_URL: z.string().url(),
  SERVICE_JWT_SECRET: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_SOCIAL: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_NEXT: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_SECRET_ISSUER: z.preprocess(emptyToUndefined, z.string().min(32).optional()),
  SERVICE_JWT_AUDIENCE: z.string().default("cuncta-internal"),
  SERVICE_JWT_AUDIENCE_SOCIAL: z.string().default("cuncta.service.social"),
  SERVICE_JWT_AUDIENCE_ISSUER: z.string().default("cuncta.service.issuer"),
  SERVICE_JWT_TTL_SECONDS: z.preprocess(toNumber(120), z.number().int().min(30).max(3600)),
  SYNC_SESSION_PERMISSION_TTL_SECONDS: z.preprocess(
    toNumber(300),
    z.number().int().min(120).max(600)
  ),
  SYNC_SESSION_EVENT_MAX_PAYLOAD_BYTES: z.preprocess(
    toNumber(2048),
    z
      .number()
      .int()
      .min(256)
      .max(32 * 1024)
  ),
  SYNC_SESSION_EVENT_RATE_BRONZE_PER_SEC: z.preprocess(
    toNumber(3),
    z.number().int().min(1).max(30)
  ),
  SYNC_SESSION_EVENT_RATE_SILVER_PER_SEC: z.preprocess(
    toNumber(6),
    z.number().int().min(1).max(60)
  ),
  SYNC_SESSION_EVENT_RATE_GOLD_PER_SEC: z.preprocess(
    toNumber(10),
    z.number().int().min(1).max(120)
  ),
  SYNC_SESSION_EVENT_BURST_MULTIPLIER: z.preprocess(toNumber(3), z.number().int().min(1).max(10)),
  SYNC_SESSION_EVENT_RETENTION_DAYS: z.preprocess(toNumber(14), z.number().int().min(1).max(180)),
  PRESENCE_PING_TTL_SECONDS: z.preprocess(toNumber(600), z.number().int().min(300).max(900)),
  PRESENCE_PING_RATE_WINDOW_SECONDS: z.preprocess(toNumber(20), z.number().int().min(5).max(120)),
  PRESENCE_PING_RATE_MAX_PER_WINDOW: z.preprocess(toNumber(10), z.number().int().min(1).max(60)),
  LEADERBOARD_TOP_N: z.preprocess(toNumber(10), z.number().int().min(3).max(50)),
  BANTER_MESSAGE_RETENTION_DAYS: z.preprocess(toNumber(10), z.number().int().min(1).max(60)),
  BANTER_STATUS_TTL_SECONDS: z.preprocess(
    toNumber(24 * 60 * 60),
    z.number().int().min(60).max(7 * 24 * 60 * 60)
  ),
  BANTER_PERMISSION_TTL_SECONDS: z.preprocess(toNumber(600), z.number().int().min(60).max(3600)),
  BANTER_RATE_WINDOW_SECONDS: z.preprocess(toNumber(10), z.number().int().min(1).max(120)),
  BANTER_RATE_BRONZE_PER_WINDOW: z.preprocess(toNumber(6), z.number().int().min(1).max(120)),
  BANTER_RATE_SILVER_PER_WINDOW: z.preprocess(toNumber(12), z.number().int().min(1).max(240)),
  BANTER_RATE_GOLD_PER_WINDOW: z.preprocess(toNumber(20), z.number().int().min(1).max(360)),
  BANTER_RATE_COOLDOWN_SECONDS: z.preprocess(toNumber(20), z.number().int().min(1).max(600)),
  REALTIME_PERMISSION_TTL_SECONDS: z.preprocess(toNumber(300), z.number().int().min(60).max(3600)),
  REALTIME_PUBLISH_RATE_WINDOW_SECONDS: z.preprocess(
    toNumber(10),
    z.number().int().min(1).max(120)
  ),
  REALTIME_PUBLISH_RATE_MAX_PER_WINDOW: z.preprocess(
    toNumber(20),
    z.number().int().min(1).max(200)
  ),
  REALTIME_EVENTS_RETENTION_DAYS: z.preprocess(toNumber(7), z.number().int().min(1).max(90)),
  REALTIME_EVENT_MAX_PAYLOAD_BYTES: z.preprocess(
    toNumber(4 * 1024),
    z.number().int().min(256).max(64 * 1024)
  ),
  MEDIA_STORAGE_PROVIDER: z.enum(["s3"]).default("s3"),
  MEDIA_S3_ENDPOINT: z.string().url().optional(),
  MEDIA_S3_REGION: z.string().default("auto"),
  MEDIA_S3_BUCKET: z.string().default("cuncta-social-media"),
  MEDIA_S3_ACCESS_KEY_ID: z.string().default("minioadmin"),
  MEDIA_S3_SECRET_ACCESS_KEY: z.string().default("minioadmin"),
  MEDIA_S3_FORCE_PATH_STYLE: z.preprocess((value) => value === "true", z.boolean()).default(true),
  MEDIA_S3_CONNECTION_TIMEOUT_MS: z.preprocess(toNumber(3000), z.number().int().min(500).max(120_000)),
  MEDIA_S3_SOCKET_TIMEOUT_MS: z.preprocess(toNumber(10_000), z.number().int().min(500).max(300_000)),
  MEDIA_S3_OP_TIMEOUT_MS: z.preprocess(toNumber(10_000), z.number().int().min(1000).max(120_000)),
  ISSUER_PRIVACY_STATUS_TIMEOUT_MS: z.preprocess(
    toNumber(2500),
    z.number().int().min(250).max(120_000)
  ),
  MEDIA_PRESIGN_TTL_SECONDS: z.preprocess(toNumber(600), z.number().int().min(60).max(3600)),
  MEDIA_PURGE_MAX_ATTEMPTS: z.preprocess(toNumber(20), z.number().int().min(1).max(200)),
  MEDIA_MAX_UPLOAD_BYTES: z.preprocess(
    toNumber(10 * 1024 * 1024),
    z.number().int().min(64 * 1024).max(100 * 1024 * 1024)
  ),
  PULSE_CHALLENGE_ENDING_SOON_SECONDS: z.preprocess(
    toNumber(2 * 60 * 60),
    z
      .number()
      .int()
      .min(300)
      .max(24 * 60 * 60)
  ),
  PULSE_RANK_NEAR_GAP: z.preprocess(toNumber(2), z.number().int().min(1).max(20)),
  ANCHOR_AUTH_SECRET: z.preprocess(emptyToUndefined, z.string().min(16).optional()),
  ALLOW_INSECURE_DEV_AUTH: z.preprocess((value) => value === "true", z.boolean()).default(false),
  ALLOW_LEGACY_SERVICE_JWT_SECRET: z
    .preprocess((value) => value === "true", z.boolean())
    .default(false)
});

const parsed = envSchema.parse(process.env);
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
const serviceBindAddress =
  parsed.SERVICE_BIND_ADDRESS ?? (parsed.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0");

export const config = {
  ...parsed,
  AUTO_MIGRATE: autoMigrate,
  STRICT_DB_ROLE: strictDbRole,
  SERVICE_BIND_ADDRESS: serviceBindAddress
};
