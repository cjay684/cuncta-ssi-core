import { z } from "zod";
import { buildPrivacyKbjwt, loadWalletState } from "./privacyKbjwt.js";

const envSchema = z.object({
  ISSUER_SERVICE_BASE_URL: z.string().url()
});

type PrivacyRequestResponse = {
  requestId: string;
  nonce: string;
  audience: string;
  expires_at: string;
};

type PrivacyConfirmResponse = {
  dsrToken: string;
  expires_at?: string;
};

export const privacyFlow = async () => {
  const env = envSchema.parse(process.env);
  const state = await loadWalletState();
  const did = state.did?.did;
  if (!did) {
    throw new Error("wallet_state_missing_did");
  }

  const requestResponse = await fetch(`${env.ISSUER_SERVICE_BASE_URL}/v1/privacy/request`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ did })
  });
  if (!requestResponse.ok) {
    const text = await requestResponse.text();
    throw new Error(`privacy_request_failed: ${text}`);
  }
  const requestPayload = (await requestResponse.json()) as PrivacyRequestResponse;

  const kbJwt = await buildPrivacyKbjwt({
    nonce: requestPayload.nonce,
    audience: requestPayload.audience
  });

  const confirmResponse = await fetch(`${env.ISSUER_SERVICE_BASE_URL}/v1/privacy/confirm`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      requestId: requestPayload.requestId,
      nonce: requestPayload.nonce,
      kbJwt
    })
  });
  if (!confirmResponse.ok) {
    const text = await confirmResponse.text();
    throw new Error(`privacy_confirm_failed: ${text}`);
  }
  const confirmPayload = (await confirmResponse.json()) as PrivacyConfirmResponse;

  console.log("DSR authentication succeeded.");
  console.log(`DSR token (short-lived): ${confirmPayload.dsrToken}`);
  console.log("Next steps:");
  console.log(
    `  curl -s "${env.ISSUER_SERVICE_BASE_URL}/v1/privacy/export" -H "authorization: Bearer ${confirmPayload.dsrToken}"`
  );
  console.log(
    `  curl -s -X POST "${env.ISSUER_SERVICE_BASE_URL}/v1/privacy/restrict" -H "authorization: Bearer ${confirmPayload.dsrToken}" -H "content-type: application/json" -d '{"reason":"user request"}'`
  );
  console.log(
    `  curl -s -X POST "${env.ISSUER_SERVICE_BASE_URL}/v1/privacy/erase" -H "authorization: Bearer ${confirmPayload.dsrToken}" -H "content-type: application/json" -d '{"mode":"unlink"}'`
  );
};
