import { z } from "zod";
import { createNodeFileKeyStore } from "./nodeFileKeyStore.js";
import { createWindowsDpapiKeyStore } from "./windowsDpapiKeyStore.js";
import type { WalletKeyStore } from "./types.js";

const ModeSchema = z.enum(["file", "dpapi", "hardware", "mobile", "webcrypto"]);

const isProd = () => (process.env.NODE_ENV ?? "development") === "production";
const allowInsecureFileKeys = () => process.env.ALLOW_INSECURE_WALLET_KEYS === "true";

export const selectWalletKeyStore = (input: {
  walletDir: string;
  filename?: string;
  mode?: string;
}): WalletKeyStore => {
  const rawMode = (
    input.mode ??
    process.env.WALLET_KEYSTORE ??
    process.env.WALLET_KEYSTORE_MODE ??
    "file"
  ).trim();
  const mode = ModeSchema.parse(rawMode);
  if (mode === "file") {
    if (isProd() && !allowInsecureFileKeys()) {
      // Production posture: raw private key material on disk is forbidden by default.
      throw new Error("insecure_file_keystore_disabled_in_production");
    }
    return createNodeFileKeyStore({ walletDir: input.walletDir, filename: input.filename });
  }
  if (mode === "dpapi") {
    if (process.platform !== "win32") {
      // Fail closed: DPAPI is Windows-only.
      throw new Error("wallet_keystore_dpapi_unavailable");
    }
    return createWindowsDpapiKeyStore({ walletDir: input.walletDir, filename: input.filename });
  }
  if (mode === "mobile") {
    // React Native secure enclave / keystore integration path.
    throw new Error("wallet_keystore_mobile_unavailable");
  }
  if (mode === "webcrypto") {
    // Browser WebCrypto + IndexedDB integration path.
    throw new Error("wallet_keystore_webcrypto_unavailable");
  }
  // "hardware" remains an integration point (future passkeys/mobile keystores).
  throw new Error("wallet_keystore_hardware_unavailable");
};
