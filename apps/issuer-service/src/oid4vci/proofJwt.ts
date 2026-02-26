import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import type { JWK } from "jose";
import { config } from "../config.js";
import { isCnfKeyAuthorizedByDidDocument } from "@cuncta/shared";

type JwkRecord = Record<string, unknown>;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const toOptionalString = (value: unknown) => {
  if (value === undefined || value === null) return undefined;
  const trimmed = String(value).trim();
  return trimmed.length ? trimmed : undefined;
};

const resolveDid = async (did: string) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("did_resolve_timeout"), config.OID4VCI_DID_RESOLVE_TIMEOUT_MS);
  timeout.unref?.();
  try {
    const url = new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, config.DID_SERVICE_BASE_URL);
    const res = await fetch(url, { method: "GET", signal: controller.signal });
    if (!res.ok) {
      throw new Error("did_resolve_failed");
    }
    const payload = (await res.json().catch(() => null)) as { didDocument?: unknown } | null;
    if (!payload?.didDocument) throw new Error("did_resolve_failed");
    return payload.didDocument;
  } finally {
    clearTimeout(timeout);
  }
};

export type VerifyOid4vciProofJwtInput = {
  proofJwt: string;
  expectedAudience: string;
  expectedNonce: string;
  expectedSubjectDid: string;
};

export const verifyOid4vciProofJwtEdDSA = async (input: VerifyOid4vciProofJwtInput) => {
  const header = decodeProtectedHeader(input.proofJwt);
  if (header.alg !== "EdDSA") {
    throw new Error("proof_jwt_invalid_alg");
  }
  // We intentionally decode unverified first to locate cnf.jwk for signature verification.
  const decoded = decodeJwt(input.proofJwt) as Record<string, unknown>;
  const cnf = decoded.cnf as { jwk?: JwkRecord } | undefined;
  if (!cnf?.jwk || !isRecord(cnf.jwk)) {
    throw new Error("proof_jwt_missing_cnf");
  }
  const holderJwk = cnf.jwk as unknown as JWK;
  const holderKey = await importJWK(holderJwk as never, "EdDSA");
  const verified = await jwtVerify(input.proofJwt, holderKey, {
    algorithms: ["EdDSA"]
  });

  const payload = verified.payload as Record<string, unknown>;
  const aud = payload.aud;
  const audOk = Array.isArray(aud)
    ? aud.map(String).includes(input.expectedAudience)
    : typeof aud === "string" && aud === input.expectedAudience;
  if (!audOk) {
    throw new Error("aud_mismatch");
  }
  if (toOptionalString(payload.nonce) !== input.expectedNonce) {
    throw new Error("nonce_mismatch");
  }
  const iss = toOptionalString(payload.iss);
  const sub = toOptionalString(payload.sub);
  if (iss !== input.expectedSubjectDid && sub !== input.expectedSubjectDid) {
    throw new Error("subject_mismatch");
  }
  if (typeof payload.exp !== "number") {
    throw new Error("proof_jwt_missing_exp");
  }

  if (config.OID4VCI_ENFORCE_DID_KEY_BINDING) {
    const didDocument = await resolveDid(input.expectedSubjectDid);
    const ok = isCnfKeyAuthorizedByDidDocument(didDocument, cnf.jwk);
    if (!ok.ok) {
      throw new Error(ok.reason);
    }
  }

  return { cnfJwk: cnf.jwk, payload };
};

