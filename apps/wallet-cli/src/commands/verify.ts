import { z } from "zod";
import { loadWalletState } from "../walletStore.js";

const envSchema = z.object({
  VERIFIER_SERVICE_BASE_URL: z.string().url()
});

export const verify = async (action = "marketplace.list_item") => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const last = state.lastPresentation;
  if (!last || last.action !== action) {
    throw new Error("presentation_missing");
  }

  const verifyUrl = `${env.VERIFIER_SERVICE_BASE_URL}/v1/verify?action=${encodeURIComponent(
    action
  )}`;
  const response = await fetch(verifyUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      presentation: last.presentation,
      nonce: last.nonce,
      audience: last.audience
    })
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`verify_failed: ${text}`);
  }
  const payload = await response.json();
  console.log(JSON.stringify(payload, null, 2));
  return payload;
};
