import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from "jose";
import { verifySdJwtVc, type VerifySdJwtVcResult } from "@cuncta/sdjwt";

type JwkRecord = Record<string, unknown>;

const base64UrlPattern = /^[A-Za-z0-9_-]+$/;

const bytesToBase64Url = (bytes: Uint8Array) => {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64url");
  }
  let binary = "";
  for (const value of bytes) {
    binary += String.fromCharCode(value);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const decodeBase64UrlStrict = (value: string) => {
  if (!value || !base64UrlPattern.test(value) || value.length % 4 === 1) {
    throw new Error("jwk_base64url_invalid");
  }
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(value, "base64url"));
  }
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "===".slice((normalized.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

const assertEd25519Jwk = (input: JwkRecord, label: string) => {
  const kty = input.kty;
  const crv = input.crv;
  const alg = input.alg;
  const x = input.x;
  if (kty !== "OKP" || crv !== "Ed25519") {
    throw new Error(`${label}_jwk_invalid`);
  }
  if (alg !== undefined && alg !== "EdDSA") {
    throw new Error(`${label}_jwk_invalid`);
  }
  if (typeof x !== "string") {
    throw new Error(`${label}_jwk_invalid`);
  }
  decodeBase64UrlStrict(x);
  return input as JwkRecord & { kty: "OKP"; crv: "Ed25519"; x: string; alg?: "EdDSA" };
};

const sha256Base64Url = async (value: string) => {
  if (globalThis.crypto?.subtle) {
    const data = new TextEncoder().encode(value);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
    return bytesToBase64Url(new Uint8Array(digest));
  }
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(value).digest("base64url");
};

const resolveIssuerKeys = (jwks: { keys: JWK[] }) => {
  const keys = jwks.keys ?? [];
  if (!keys.length) {
    throw new Error("jwks_missing");
  }
  return keys.map((key) => assertEd25519Jwk(key as JwkRecord, "issuer")) as JWK[];
};

export const computeSdHash = async (sdJwtPresentation: string) => {
  return sha256Base64Url(sdJwtPresentation);
};

export const verifySdJwtPresentation = async (input: {
  presentation: string;
  issuerJwks: { keys: JWK[] };
  allowLegacyTyp?: boolean;
}): Promise<VerifySdJwtVcResult> => {
  const keys = resolveIssuerKeys(input.issuerJwks);
  return verifySdJwtVc({
    token: input.presentation,
    jwks: { keys },
    allowLegacyTyp: input.allowLegacyTyp
  });
};

export const verifyKbJwtBinding = async (input: {
  kbJwt: string;
  audience: string;
  nonce: string;
  sdJwtPresentation?: string;
  sdHash?: string;
}) => {
  const header = decodeProtectedHeader(input.kbJwt);
  if (header.alg !== "EdDSA") {
    throw new Error("kb_jwt_invalid_alg");
  }
  const decoded = decodeJwt(input.kbJwt) as Record<string, unknown>;
  const cnf = decoded.cnf as { jwk?: JwkRecord } | undefined;
  if (!cnf?.jwk) {
    throw new Error("kb_jwt_missing_cnf");
  }
  const holderJwk = assertEd25519Jwk(cnf.jwk, "holder");
  const holderKey = await importJWK(holderJwk as never, "EdDSA");
  const { payload } = await jwtVerify(input.kbJwt, holderKey);
  if (typeof payload.exp !== "number") {
    throw new Error("kb_jwt_missing_exp");
  }
  const kbAud = payload.aud;
  const audValid = Array.isArray(kbAud)
    ? kbAud.map(String).includes(input.audience)
    : typeof kbAud === "string" && kbAud === input.audience;
  if (!audValid) {
    throw new Error(typeof kbAud === "undefined" ? "kb_jwt_missing_aud" : "aud_mismatch");
  }
  const kbNonce = payload.nonce;
  if (typeof kbNonce !== "string") {
    throw new Error("kb_jwt_missing_nonce");
  }
  if (kbNonce !== input.nonce) {
    throw new Error("nonce_mismatch");
  }
  const sdHash = payload.sd_hash;
  if (typeof sdHash !== "string") {
    throw new Error("kb_jwt_missing_sd_hash");
  }
  const expectedSdHash = input.sdJwtPresentation
    ? await computeSdHash(input.sdJwtPresentation)
    : input.sdHash;
  if (!expectedSdHash) {
    throw new Error("sd_hash_required");
  }
  if (sdHash !== expectedSdHash) {
    throw new Error("sd_hash_mismatch");
  }
  return payload;
};

const decodeBitstring = (encoded: string) => decodeBase64UrlStrict(encoded);

const isBitSet = (bytes: Uint8Array, index: number) => {
  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;
  return (bytes[byteIndex] & (1 << bitIndex)) !== 0;
};

const verifyStatusListSignature = async (
  vc: Record<string, unknown>,
  issuerJwks: { keys: JWK[] }
) => {
  const proof = vc.proof as Record<string, unknown> | undefined;
  const proofJwt = proof?.jwt as string | undefined;
  if (!proofJwt) {
    throw new Error("status_list_invalid_signature");
  }
  const header = decodeProtectedHeader(proofJwt);
  if (header.alg !== "EdDSA") {
    throw new Error("status_list_invalid_signature");
  }
  const keys = resolveIssuerKeys(issuerJwks);
  const jwk = keys.find((key) => (key.kid ? key.kid === header.kid : true));
  if (!jwk) {
    throw new Error("status_list_invalid_signature");
  }
  const key = await importJWK(jwk as never, "EdDSA");
  const { payload } = await jwtVerify(proofJwt, key);
  if (!payload || typeof payload !== "object") {
    throw new Error("status_list_invalid_signature");
  }
  return payload as Record<string, unknown>;
};

export const verifyStatusListEntry = async (input: {
  status: Record<string, unknown>;
  issuerJwks: { keys: JWK[] };
  issuerBaseUrl?: string;
  fetchImpl?: typeof fetch;
}) => {
  const listCredential = input.status.statusListCredential as string | undefined;
  const index = input.status.statusListIndex as string | undefined;
  if (!listCredential || !index) {
    return { valid: false, reason: "missing_status_fields" };
  }
  const parsedIndex = Number(index);
  if (!Number.isInteger(parsedIndex) || parsedIndex < 0) {
    return { valid: false, reason: "status_list_index_invalid" };
  }
  const listUrl = input.issuerBaseUrl
    ? new URL(listCredential, input.issuerBaseUrl).toString()
    : listCredential;
  const fetcher = input.fetchImpl ?? fetch;
  const response = await fetcher(listUrl);
  if (!response.ok) {
    return { valid: false, reason: "status_list_fetch_failed" };
  }
  const rawVc = (await response.json()) as Record<string, unknown>;
  try {
    const verifiedVc = await verifyStatusListSignature(rawVc, input.issuerJwks);
    const encodedList = (verifiedVc.credentialSubject as Record<string, unknown>)?.encodedList as
      | string
      | undefined;
    if (!encodedList) {
      return { valid: false, reason: "status_list_missing" };
    }
    const bytes = decodeBitstring(encodedList);
    const revoked = isBitSet(bytes, parsedIndex);
    return { valid: !revoked, reason: revoked ? "revoked" : undefined };
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : "status_list_invalid_signature"
    };
  }
};
