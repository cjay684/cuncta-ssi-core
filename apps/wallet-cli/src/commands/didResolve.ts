import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";

const envSchema = z.object({
  DID_SERVICE_BASE_URL: z.string().url(),
  APP_GATEWAY_BASE_URL: z.string().url().optional()
});

type WalletState = {
  did: {
    did: string;
  };
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

export const didResolve = async () => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  if (!state?.did?.did) {
    throw new Error("No DID found in wallet-state.json.");
  }

  const serviceUrl = new URL(env.APP_GATEWAY_BASE_URL ?? env.DID_SERVICE_BASE_URL);
  const response = await fetch(
    new URL(`/v1/dids/resolve/${encodeURIComponent(state.did.did)}`, serviceUrl)
  );

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`resolve failed: ${errorText}`);
  }

  const payload = await response.json();
  console.log(JSON.stringify(payload, null, 2));
};
