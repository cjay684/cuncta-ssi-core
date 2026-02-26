import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { z } from "zod";

const envSchema = z.object({
  ISSUER_SERVICE_BASE_URL: z.string().url()
});

type WalletState = {
  did?: { did?: string };
  credentials?: Array<{
    vct: string;
    credential: string;
    eventId: string;
    credentialFingerprint: string;
  }>;
};

const walletStatePath = () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return path.join(dir, "..", "..", "wallet-state.json");
};

const loadWalletState = async (): Promise<WalletState> => {
  const content = await readFile(walletStatePath(), "utf8");
  return JSON.parse(content) as WalletState;
};

const saveWalletState = async (state: WalletState) => {
  await writeFile(walletStatePath(), JSON.stringify(state, null, 2), "utf8");
};

export const auraClaim = async (outputVct = "cuncta.marketplace.seller_good_standing") => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const subjectDid = state.did?.did;
  if (!subjectDid) {
    throw new Error("holder_did_missing");
  }

  const claimUrl = `${env.ISSUER_SERVICE_BASE_URL}/v1/aura/claim`;
  const response = await fetch(claimUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subjectDid, output_vct: outputVct })
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`aura_claim_failed: ${text}`);
  }
  const payload = (await response.json()) as {
    output_vct: string;
    credential: string;
    eventId: string;
    credentialFingerprint: string;
  };

  const next = state.credentials?.filter((cred) => cred.vct !== payload.output_vct) ?? [];
  next.push({
    vct: payload.output_vct,
    credential: payload.credential,
    eventId: payload.eventId,
    credentialFingerprint: payload.credentialFingerprint
  });
  state.credentials = next;
  await saveWalletState(state);
  console.log(`aura_claimed=${payload.output_vct}`);
};
