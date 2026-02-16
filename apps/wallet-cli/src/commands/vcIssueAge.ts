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
    sdJwt: string;
    credentialId?: string;
    eventId?: string;
    credentialFingerprint?: string;
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

export const vcIssueAge = async () => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const subjectDid = state.did?.did;
  if (!subjectDid) {
    throw new Error("holder_did_missing");
  }

  const catalogUrl = `${env.ISSUER_SERVICE_BASE_URL}/v1/catalog/credentials/cuncta.age_over_18`;
  let catalogResponse: Response;
  try {
    catalogResponse = await fetch(catalogUrl);
  } catch (error) {
    throw new Error(
      `catalog fetch failed: ${catalogUrl} (${error instanceof Error ? error.message : String(error)})`
    );
  }
  if (!catalogResponse.ok) {
    const text = await catalogResponse.text();
    throw new Error(`catalog fetch failed: ${text}`);
  }
  const catalog = (await catalogResponse.json()) as { vct?: string; lane?: string };
  if (catalog.vct !== "cuncta.age_over_18") {
    throw new Error("catalog_entry_invalid");
  }

  const issueUrl = `${env.ISSUER_SERVICE_BASE_URL}/v1/dev/issue`;
  let response: Response;
  try {
    response = await fetch(issueUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subjectDid,
        vct: "cuncta.age_over_18",
        claims: { age_over_18: true },
        statusListId: "default"
      })
    });
  } catch (error) {
    throw new Error(
      `issue failed: ${issueUrl} (${error instanceof Error ? error.message : String(error)})`
    );
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`issue failed: ${text}`);
  }
  const payload = (await response.json()) as {
    credentialId?: string;
    sdJwt?: string;
    eventId?: string;
    credential?: string;
    credentialFingerprint?: string;
  };
  const sdJwt = payload.sdJwt ?? payload.credential;
  if (!sdJwt) {
    throw new Error("issued_credential_missing");
  }

  const credentials = state.credentials ?? [];
  const next = credentials.filter(
    (cred) => cred.credentialId !== payload.credentialId && cred.vct !== "cuncta.age_over_18"
  );
  next.push({
    vct: "cuncta.age_over_18",
    sdJwt,
    credentialId: payload.credentialId,
    eventId: payload.eventId,
    credentialFingerprint: payload.credentialFingerprint
  });
  state.credentials = next;
  await saveWalletState(state);
  if (payload.eventId) {
    console.log(`eventId=${payload.eventId}`);
  } else if (payload.credentialId) {
    console.log(`credentialId=${payload.credentialId}`);
  }
};
