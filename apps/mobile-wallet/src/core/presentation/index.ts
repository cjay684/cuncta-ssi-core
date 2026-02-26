import { presentSdJwtVc } from "@cuncta/sdjwt";
import { createHash } from "node:crypto";
import { KeyManager } from "../keys/types.js";

const base64url = (input: Uint8Array | string) =>
  Buffer.from(typeof input === "string" ? input : input).toString("base64url");

export const computeSdHash = (presentation: string) =>
  base64url(createHash("sha256").update(presentation, "utf8").digest());

export const buildSdJwtPresentation = async (input: { sdJwt: string; disclosures?: string[] }) => {
  return presentSdJwtVc({
    sdJwt: input.sdJwt,
    disclose: input.disclosures ?? []
  });
};

export const buildKbJwtBinding = async (input: {
  keyManager: KeyManager;
  holderKeyRef: { id: string; type: "holder" };
  audience: string;
  nonce: string;
  expiresInSeconds: number;
  sdJwtPresentation: string;
  nowSeconds?: number;
}) => {
  const nowSeconds = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const holderJwk = await input.keyManager.getHolderPublicJwk(input.holderKeyRef);
  const header = { alg: "EdDSA", typ: "kb+jwt" };
  const payload = {
    aud: input.audience,
    nonce: input.nonce,
    iat: nowSeconds,
    exp: nowSeconds + input.expiresInSeconds,
    sd_hash: computeSdHash(input.sdJwtPresentation),
    cnf: {
      jwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: String(holderJwk.x),
        alg: "EdDSA"
      }
    }
  };
  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(payload));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = await input.keyManager.signWithHolderKey(
    input.holderKeyRef,
    Buffer.from(signingInput, "utf8")
  );
  const signatureB64 = base64url(signature);
  return `${signingInput}.${signatureB64}`;
};

export const buildVerifyRequest = (input: {
  sdJwtPresentation: string;
  kbJwt: string;
  nonce: string;
  audience: string;
}) => {
  const presentation = `${input.sdJwtPresentation}${input.kbJwt}`;
  return {
    presentation,
    nonce: input.nonce,
    audience: input.audience
  };
};
