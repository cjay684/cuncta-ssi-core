import { importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { randomUUID } from "node:crypto";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { config } from "../config.js";
import { getDb } from "../db.js";
import { writeAuditLog } from "../audit.js";
import { metrics } from "../metrics.js";

type PolicyRow = {
  policy_id: string;
  action_id: string;
  version: number;
  enabled: boolean;
  logic: unknown;
  policy_hash?: string | null;
  policy_signature?: string | null;
};

let cachedJwk: JWK | null = null;
let cachedSigningKey: Awaited<ReturnType<typeof importJWK>> | null = null;
let cachedVerifyKey: Awaited<ReturnType<typeof importJWK>> | null = null;

export const resetPolicyIntegrityCache = () => {
  cachedJwk = null;
  cachedSigningKey = null;
  cachedVerifyKey = null;
};

const loadPolicyJwk = () => {
  if (cachedJwk) return cachedJwk;
  if (!config.POLICY_SIGNING_JWK) {
    throw new Error("policy_integrity_failed");
  }
  let parsed: JWK;
  try {
    parsed = JSON.parse(config.POLICY_SIGNING_JWK) as JWK;
  } catch {
    throw new Error("policy_integrity_failed");
  }
  if (!parsed.kid) {
    parsed.kid = "policy-1";
  }
  cachedJwk = parsed;
  return parsed;
};

const getSigningKey = async () => {
  if (cachedSigningKey) return cachedSigningKey;
  const jwk = loadPolicyJwk();
  cachedSigningKey = await importJWK(jwk, "EdDSA");
  return cachedSigningKey;
};

const getVerifyKey = async () => {
  if (cachedVerifyKey) return cachedVerifyKey;
  const jwk = loadPolicyJwk();
  const { d, ...publicJwk } = jwk as JWK & { d?: string };
  void d;
  cachedVerifyKey = await importJWK(publicJwk, "EdDSA");
  return cachedVerifyKey;
};

export const computePolicyHash = (row: PolicyRow) => {
  return hashCanonicalJson({
    policy_id: row.policy_id,
    action_id: row.action_id,
    version: row.version,
    enabled: row.enabled,
    logic: row.logic
  });
};

const signPolicyHash = async (policyHash: string) => {
  const key = await getSigningKey();
  const jwk = loadPolicyJwk();
  return new SignJWT({ hash: policyHash })
    .setProtectedHeader({ alg: "EdDSA", typ: "policy-hash+jwt", kid: jwk.kid })
    .setIssuedAt()
    .sign(key);
};

const verifyPolicySignature = async (policyHash: string, signature: string) => {
  try {
    const key = await getVerifyKey();
    const { payload } = await jwtVerify(signature, key);
    if (!payload || typeof payload !== "object") {
      throw new Error("policy_integrity_failed");
    }
    if (payload.hash !== policyHash) {
      throw new Error("policy_integrity_failed");
    }
  } catch {
    throw new Error("policy_integrity_failed");
  }
};

const enqueuePolicyAnchor = async (policyHash: string, row: PolicyRow) => {
  if (!config.ANCHOR_AUTH_SECRET) {
    throw new Error("anchor_auth_secret_missing");
  }
  const payloadMeta = {
    policy_id: row.policy_id,
    action_id: row.action_id,
    version: row.version,
    ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
      payloadHash: policyHash,
      eventType: "POLICY_CHANGE"
    })
  };
  const db = await getDb();
  await db("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: "POLICY_CHANGE",
      payload_hash: policyHash,
      payload_meta: payloadMeta,
      status: "PENDING",
      attempts: 0,
      next_retry_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .onConflict("payload_hash")
    .ignore();
};

const recordPolicyChange = async (policyHash: string, row: PolicyRow) => {
  const db = await getDb();
  const key = `policy_hash:${row.policy_id}`;
  const existing = await db("system_metadata").where({ key }).first();
  if (existing?.value === policyHash) {
    return;
  }
  await db("system_metadata")
    .insert({ key, value: policyHash, updated_at: new Date().toISOString() })
    .onConflict("key")
    .merge({ value: policyHash, updated_at: new Date().toISOString() });
  await writeAuditLog("policy_change", {
    entityId: row.policy_id,
    policy_id: row.policy_id,
    action_id: row.action_id,
    version: row.version,
    policy_hash: policyHash
  });
  metrics.incCounter("policy_change_total", {});
  await enqueuePolicyAnchor(policyHash, row);
};

export const ensurePolicyIntegrity = async (row: PolicyRow) => {
  const policyHash = computePolicyHash(row);
  if (!row.policy_hash || !row.policy_signature) {
    if (!config.POLICY_SIGNING_BOOTSTRAP) {
      throw new Error("policy_integrity_failed");
    }
    const signature = await signPolicyHash(policyHash);
    const db = await getDb();
    await db("policies").where({ policy_id: row.policy_id }).update({
      policy_hash: policyHash,
      policy_signature: signature,
      updated_at: new Date().toISOString()
    });
    await recordPolicyChange(policyHash, row);
    return { policyHash, signature };
  }
  if (row.policy_hash !== policyHash) {
    throw new Error("policy_integrity_failed");
  }
  await verifyPolicySignature(policyHash, row.policy_signature);
  await recordPolicyChange(policyHash, row);
  return { policyHash, signature: row.policy_signature };
};
