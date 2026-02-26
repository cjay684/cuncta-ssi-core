import { config } from "../config.js";
import { generateDiBbsKeyPair, type DiBbsKeyPair } from "@cuncta/di-bbs";

let cached: DiBbsKeyPair | null = null;

export const getIssuerDiBbsKeyPair = async (): Promise<DiBbsKeyPair> => {
  if (cached) return cached;
  const sk = config.ISSUER_BBS_SECRET_KEY_B64U;
  const pk = config.ISSUER_BBS_PUBLIC_KEY_B64U;
  if (sk && pk) {
    cached = {
      secretKey: Uint8Array.from(Buffer.from(sk, "base64url")),
      publicKey: Uint8Array.from(Buffer.from(pk, "base64url"))
    };
    return cached;
  }
  // Dev-only fallback: generate ephemeral keys if not configured.
  if (config.NODE_ENV !== "production") {
    cached = await generateDiBbsKeyPair();
    return cached;
  }
  throw new Error("issuer_bbs_keys_missing");
};

