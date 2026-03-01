import { randomBytes, createHash } from "node:crypto";
import { getDb } from "../db.js";
import { hashCanonicalJson } from "@cuncta/shared";

const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

export type CreatePreauthCodeInput = {
  vct: string;
  ttlSeconds: number;
  txCode?: string | null;
  // Optional context for preauth codes (hash-only/TTL store).
  // Used for capability issuance to bind scope (e.g. space_id) without storing any raw DID.
  scope?: Record<string, unknown> | null;
};

export const createPreauthCode = async (input: CreatePreauthCodeInput) => {
  const db = await getDb();
  const code = randomBytes(32).toString("base64url");
  const codeHash = sha256Hex(code);
  const txCodeHash = input.txCode ? sha256Hex(input.txCode) : null;
  // IMPORTANT: persist hash-only (GDPR minimization). Raw scope is client-supplied at redemption time.
  const scopeHash = input.scope ? hashCanonicalJson(input.scope) : null;
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();
  const baseRow = {
    code_hash: codeHash,
    vct: input.vct,
    tx_code_hash: txCodeHash,
    expires_at: expiresAt,
    consumed_at: null,
    created_at: new Date().toISOString()
  };
  try {
    await db("oid4vci_preauth_codes").insert({
      ...baseRow,
      scope_hash: scopeHash
    });
  } catch {
    // Backward compatibility: older dev DBs might not have scope columns yet.
    await db("oid4vci_preauth_codes").insert(baseRow);
  }
  return { preAuthorizedCode: code, expiresAt };
};

export const consumePreauthCode = async (input: { code: string; txCode?: string | null }) => {
  const db = await getDb();
  const codeHash = sha256Hex(input.code);
  const now = new Date().toISOString();
  const row = await db("oid4vci_preauth_codes").where({ code_hash: codeHash }).first();
  if (!row) {
    throw new Error("preauth_code_invalid");
  }
  if (row.consumed_at) {
    throw new Error("preauth_code_consumed");
  }
  if (row.expires_at && new Date(row.expires_at as string) <= new Date()) {
    throw new Error("preauth_code_expired");
  }
  const txCodeHash = row.tx_code_hash as string | null | undefined;
  if (txCodeHash) {
    if (!input.txCode) {
      throw new Error("tx_code_required");
    }
    if (sha256Hex(input.txCode) !== txCodeHash) {
      throw new Error("tx_code_invalid");
    }
  }
  // One-time semantics: consume on successful token redemption.
  const updated = await db("oid4vci_preauth_codes")
    .where({ code_hash: codeHash })
    .whereNull("consumed_at")
    .andWhere("expires_at", ">", now)
    .update({ consumed_at: now });
  if (!updated) {
    throw new Error("preauth_code_consumed");
  }
  const scopeHash = String((row as { scope_hash?: unknown }).scope_hash ?? "").trim() || null;
  return { vct: String(row.vct ?? ""), scopeHash };
};

export const sha256HexString = (value: string) => sha256Hex(value);

export const createCNonce = async (input: { tokenJti: string; ttlSeconds: number }) => {
  const db = await getDb();
  const cNonce = randomBytes(32).toString("base64url");
  const nonceHash = sha256Hex(cNonce);
  const tokenJtiHash = sha256Hex(input.tokenJti);
  const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();
  await db("oid4vci_c_nonces").insert({
    nonce_hash: nonceHash,
    token_jti_hash: tokenJtiHash,
    expires_at: expiresAt,
    consumed_at: null,
    created_at: new Date().toISOString()
  });
  return { cNonce, expiresAt };
};

export const consumeCNonce = async (input: { cNonce: string; tokenJti: string }) => {
  const db = await getDb();
  const nonceHash = sha256Hex(input.cNonce);
  const tokenJtiHash = sha256Hex(input.tokenJti);
  const now = new Date().toISOString();
  const updated = await db("oid4vci_c_nonces")
    .where({ nonce_hash: nonceHash, token_jti_hash: tokenJtiHash })
    .whereNull("consumed_at")
    .andWhere("expires_at", ">", now)
    .update({ consumed_at: now });
  if (!updated) {
    throw new Error("c_nonce_invalid_or_consumed");
  }
};
