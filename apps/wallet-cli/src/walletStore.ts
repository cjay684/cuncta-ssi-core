import path from "node:path";
import { fileURLToPath } from "node:url";
import { readFile } from "node:fs/promises";
import { WalletStore, type WalletState } from "@cuncta/wallet";

const repoRootFromThisFile = () => {
  // .../apps/wallet-cli/src/walletStore.ts -> repo root
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "..");
};

const resolveWalletDir = () => {
  const repoRoot = repoRootFromThisFile();
  const raw = process.env.WALLET_DIR?.trim();
  if (!raw) return path.join(repoRoot, ".tmp-wallet");
  return path.isAbsolute(raw) ? raw : path.join(repoRoot, raw);
};

const legacyWalletStatePath = () => {
  const repoRoot = repoRootFromThisFile();
  return path.join(repoRoot, "apps", "wallet-cli", "wallet-state.json");
};

const store = new WalletStore({ walletDir: resolveWalletDir(), filename: "wallet-state.json" });

export const walletPaths = {
  walletDir: () => store.walletDir,
  statePath: () => store.statePath(),
  legacyStatePath: legacyWalletStatePath
};

export const loadWalletState = async (): Promise<WalletState> => {
  const state = await store.load();
  if (Object.keys(state).length > 0) return state;

  // Best-effort migration: if the legacy file exists, import it into `.tmp-wallet/`.
  const legacyRaw = await readFile(legacyWalletStatePath(), "utf8").catch(() => "");
  if (!legacyRaw) return state;
  const legacyParsed = JSON.parse(legacyRaw) as WalletState;
  await store.save(legacyParsed);
  return legacyParsed;
};

export const saveWalletState = async (next: WalletState) => {
  await store.save(next);
};

