import dotenv from "dotenv";
import path from "node:path";
import { z } from "zod";

dotenv.config({
  path: path.resolve(process.cwd(), "../../.env")
});

const envSchema = z.object({
  APP_GATEWAY_BASE_URL: z.string().url(),
  HEDERA_NETWORK: z.enum(["testnet", "previewnet", "mainnet"]).default("testnet"),
  WALLET_BUILD_MODE: z.enum(["development", "production"]).default("development"),
  NODE_ENV: z.string().optional(),
  ALLOW_MAINNET: z.preprocess((value) => value === "true", z.boolean()).default(false),
  WALLET_ALLOW_SOFTWARE_KEYS: z.preprocess((value) => value === "true", z.boolean()).default(false),
  WALLET_VAULT_KEY: z.string().min(32).optional(),
  WALLET_DEVICE_ID: z.string().optional(),
  USER_PAYS_MAX_FEE_TINYBARS: z.preprocess((value) => {
    if (value === undefined || value === null || value === "") return 50_000_000;
    const parsed = Number(value);
    return Number.isNaN(parsed) ? 50_000_000 : parsed;
  }, z.number().int().min(1))
});

export type WalletConfig = z.infer<typeof envSchema> & {
  deviceId: string;
};

export const loadConfig = (): WalletConfig => {
  const parsed = envSchema.parse(process.env);
  const nodeEnvProd = parsed.NODE_ENV === "production";
  const buildMode = nodeEnvProd ? "production" : parsed.WALLET_BUILD_MODE;
  const deviceId = parsed.WALLET_DEVICE_ID?.trim() || "mobile-wallet-device";
  if (parsed.HEDERA_NETWORK === "mainnet" && !parsed.ALLOW_MAINNET) {
    throw new Error("ALLOW_MAINNET must be true when HEDERA_NETWORK=mainnet.");
  }
  if (parsed.WALLET_VAULT_KEY) {
    validateVaultKeyMaterial(parsed.WALLET_VAULT_KEY);
  }
  return { ...parsed, WALLET_BUILD_MODE: buildMode, deviceId };
};

export const assertSoftwareKeysAllowed = (config: WalletConfig) => {
  const isProd = config.WALLET_BUILD_MODE === "production";
  if (!config.WALLET_ALLOW_SOFTWARE_KEYS) {
    throw new Error("WALLET_ALLOW_SOFTWARE_KEYS must be true for software keys.");
  }
  if (isProd) {
    throw new Error("Software keys are not allowed in production mode.");
  }
};

export const validateVaultKeyMaterial = (value: string) => {
  const trimmed = value.trim();
  if (/^[a-fA-F0-9]+$/.test(trimmed)) {
    if (trimmed.length !== 64) {
      throw new Error("WALLET_VAULT_KEY hex must be 32 bytes (64 hex chars).");
    }
    return;
  }
  try {
    const decoded = Buffer.from(trimmed, "base64url");
    if (decoded.length !== 32) {
      throw new Error("WALLET_VAULT_KEY base64url must be 32 bytes.");
    }
  } catch {
    throw new Error("WALLET_VAULT_KEY must be hex or base64url-encoded 32 bytes.");
  }
};
