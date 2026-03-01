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

const constantTimeEqualHex = (a: string, b: string) => {
  if (a.length !== b.length) return false;
  // Avoid timing leaks (best effort; inputs are hex strings).
  let out = 0;
  for (let i = 0; i < a.length; i += 1) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
};

export const verifyAnchorMeta = (
  secret: string,
  input: {
    payloadHash: string;
    eventType: string;
    anchor_auth_sig?: unknown;
    anchor_auth_ts?: unknown;
  }
): { ok: true } | { ok: false; reason: "missing_auth" | "invalid_auth" | "invalid_format" } => {
  const sig = input.anchor_auth_sig;
  const ts = input.anchor_auth_ts;
  if (sig === undefined || sig === null || ts === undefined || ts === null) {
    return { ok: false, reason: "missing_auth" };
  }
  if (typeof sig !== "string" || typeof ts !== "string") {
    return { ok: false, reason: "invalid_format" };
  }
  if (!/^[a-fA-F0-9]{64}$/.test(sig)) {
    return { ok: false, reason: "invalid_format" };
  }
  // Timestamp comes from ISO string; we don't enforce strict parsing here to preserve compatibility.
  const message = `${input.payloadHash}:${input.eventType}:${ts}`;
  const expected = createHmac("sha256", secret).update(message).digest("hex");
  if (!constantTimeEqualHex(expected, sig.toLowerCase())) {
    return { ok: false, reason: "invalid_auth" };
  }
  return { ok: true };
};
