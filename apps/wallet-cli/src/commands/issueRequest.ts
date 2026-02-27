import { z } from "zod";
import { loadWalletState, saveWalletState } from "../walletStore.js";

const envSchema = z.object({
  ISSUER_SERVICE_BASE_URL: z.string().url()
});

export const issueRequest = async () => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const subjectDid = state.did?.did;
  if (!subjectDid) {
    throw new Error("holder_did_missing");
  }

  const issueUrl = `${env.ISSUER_SERVICE_BASE_URL}/v1/issue`;
  const response = await fetch(issueUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      subjectDid,
      vct: "cuncta.marketplace.seller_good_standing",
      claims: {
        seller_good_standing: true,
        domain: "marketplace",
        as_of: new Date().toISOString(),
        tier: "bronze"
      }
    })
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`issue_failed: ${text}`);
  }
  const payload = (await response.json()) as {
    credential: string;
    eventId: string;
    credentialFingerprint: string;
  };

  const next =
    state.credentials?.filter((cred) => cred.vct !== "cuncta.marketplace.seller_good_standing") ??
    [];
  next.push({
    vct: "cuncta.marketplace.seller_good_standing",
    credential: payload.credential,
    eventId: payload.eventId,
    credentialFingerprint: payload.credentialFingerprint
  });
  state.credentials = next;
  await saveWalletState(state);
  console.log(`eventId=${payload.eventId}`);
};
