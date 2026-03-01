import path from "node:path";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { z } from "zod";
import type { WalletState } from "./types.js";

const emptyToUndefined = (value: unknown) => (value === "" ? undefined : value);

const walletStateSchema: z.ZodType<WalletState> = z
  .object({
    keys: z
      .object({
        // Newer wallet-cli stores holder public key material here (private key stays in keystore).
        holder: z
          .object({
            alg: z.literal("Ed25519"),
            publicKeyBase64: z.string().min(16),
            publicKeyMultibase: z.string().min(3)
          })
          .optional(),
        ed25519: z
          .object({
            privateKeyBase64: z.string().min(16),
            publicKeyBase64: z.string().min(16),
            publicKeyMultibase: z.string().min(3).optional()
          })
          .optional()
      })
      // Wallet state is a dev/test artifact; preserve forward-compatible keys buckets.
      .passthrough()
      .optional(),
    did: z
      .object({
        did: z.string().min(3),
        topicId: z.preprocess(emptyToUndefined, z.string().min(3).optional()),
        transactionId: z.preprocess(emptyToUndefined, z.string().min(3).optional())
      })
      .optional(),
    credentials: z
      .array(
        z
          .object({
            vct: z.string().min(1),
            // SD-JWT is a compact string; DI+BBS credentials are JSON objects.
            credential: z.union([z.string().min(10), z.record(z.string(), z.unknown())]),
            // Legacy wallet-cli used `sdJwt` in some commands; keep permissive parsing.
            sdJwt: z.union([z.string().min(10), z.record(z.string(), z.unknown())]).optional(),
            credentialId: z.string().min(1).optional(),
            eventId: z.string().min(1).optional(),
            credentialFingerprint: z.string().min(1).optional()
          })
          .passthrough()
      )
      .optional(),
    lastPresentation: z
      .object({
        action: z.string().min(1),
        presentation: z.string().min(10),
        nonce: z.string().min(10),
        audience: z.string().min(3)
      })
      .optional()
  })
  // Wallet state is a dev/test artifact; stay backwards-compatible across CLI iterations.
  .passthrough();

export type WalletStoreOptions = {
  walletDir: string;
  filename?: string;
};

export class WalletStore {
  readonly walletDir: string;
  readonly filename: string;

  constructor(options: WalletStoreOptions) {
    this.walletDir = options.walletDir;
    this.filename = options.filename ?? "wallet-state.json";
  }

  statePath() {
    return path.join(this.walletDir, this.filename);
  }

  async ensureDir() {
    await mkdir(this.walletDir, { recursive: true });
  }

  async load(): Promise<WalletState> {
    const p = this.statePath();
    const raw = await readFile(p, "utf8").catch(() => "");
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    return walletStateSchema.parse(parsed);
  }

  async save(next: WalletState) {
    await this.ensureDir();
    const p = this.statePath();
    const json = JSON.stringify(next, null, 2);
    await writeFile(p, json, "utf8");
  }
}
