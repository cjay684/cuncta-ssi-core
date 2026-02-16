import { createHmac } from "node:crypto";

export const signAnchorMeta = (
  secret: string,
  input: { payloadHash: string; eventType: string }
) => {
  const timestamp = new Date().toISOString();
  const message = `${input.payloadHash}:${input.eventType}:${timestamp}`;
  const signature = createHmac("sha256", secret).update(message).digest("hex");
  return {
    anchor_auth_sig: signature,
    anchor_auth_ts: timestamp
  };
};
