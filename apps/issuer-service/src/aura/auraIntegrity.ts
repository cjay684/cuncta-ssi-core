import { importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { randomUUID } from "node:crypto";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { config } from "../config.js";
import { getDb } from "../db.js";
import { writeAuditLog } from "../audit.js";
import { metrics } from "../metrics.js";
import { getRulePurpose, isDomainPatternValid, parseRuleLogic } from "./ruleContract.js";

type AuraRuleRow = {
  rule_id: string;
  domain: string;
  output_vct: string;
  rule_logic: unknown;
  enabled: boolean;
  version: number;
  rule_signature?: string | null;
};

let cachedJwk: JWK | null = null;
let cachedSigningKey: Awaited<ReturnType<typeof importJWK>> | null = null;
let cachedVerifyKey: Awaited<ReturnType<typeof importJWK>> | null = null;

const loadPolicyJwk = () => {
  if (cachedJwk) return cachedJwk;
  if (!config.POLICY_SIGNING_JWK) {
    throw new Error("aura_integrity_failed");
  }
  let parsed: JWK;
  try {
    parsed = JSON.parse(config.POLICY_SIGNING_JWK) as JWK;
  } catch {
    throw new Error("aura_integrity_failed");
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

export const computeAuraRuleHash = (row: AuraRuleRow) => {
  return hashCanonicalJson({
    rule_id: row.rule_id,
    domain: row.domain,
    output_vct: row.output_vct,
    rule_logic: row.rule_logic,
    enabled: row.enabled,
    version: row.version
  });
};

const signAuraRuleHash = async (ruleHash: string) => {
  const key = await getSigningKey();
  const jwk = loadPolicyJwk();
  return new SignJWT({ hash: ruleHash })
    .setProtectedHeader({ alg: "EdDSA", typ: "aura-rule-hash+jwt", kid: jwk.kid })
    .setIssuedAt()
    .sign(key);
};

const verifyAuraRuleSignature = async (ruleHash: string, signature: string) => {
  try {
    const key = await getVerifyKey();
    const { payload } = await jwtVerify(signature, key);
    if (!payload || typeof payload !== "object") {
      throw new Error("aura_integrity_failed");
    }
    if (payload.hash !== ruleHash) {
      throw new Error("aura_integrity_failed");
    }
  } catch {
    throw new Error("aura_integrity_failed");
  }
};

const enqueueAuraRuleAnchor = async (ruleHash: string, row: AuraRuleRow) => {
  if (!config.ANCHOR_AUTH_SECRET) {
    throw new Error("anchor_auth_secret_missing");
  }
  const payloadMeta = {
    rule_id: row.rule_id,
    domain: row.domain,
    output_vct: row.output_vct,
    version: row.version,
    ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
      payloadHash: ruleHash,
      eventType: "AURA_RULE_CHANGE"
    })
  };
  const db = await getDb();
  await db("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: "AURA_RULE_CHANGE",
      payload_hash: ruleHash,
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

const recordAuraRuleChange = async (ruleHash: string, row: AuraRuleRow) => {
  const db = await getDb();
  const key = `aura_rule_hash:${row.rule_id}`;
  const existing = await db("system_metadata").where({ key }).first();
  if (existing?.value === ruleHash) {
    return;
  }
  await db("system_metadata")
    .insert({ key, value: ruleHash, updated_at: new Date().toISOString() })
    .onConflict("key")
    .merge({ value: ruleHash, updated_at: new Date().toISOString() });
  await writeAuditLog("aura_rule_change", {
    entityId: row.rule_id,
    rule_id: row.rule_id,
    domain: row.domain,
    output_vct: row.output_vct,
    version: row.version,
    rule_hash: ruleHash
  });
  metrics.incCounter("aura_rule_change_total", {});
  await enqueueAuraRuleAnchor(ruleHash, row);
};

export const verifyAuraRuleIntegrity = async (row: AuraRuleRow) => {
  // Same contract validation as ensureAuraRuleIntegrity, but with NO side effects:
  // - does not sign missing signatures
  // - does not write audit logs
  // - does not enqueue anchors
  if (row.enabled) {
    const outputVct = String(row.output_vct ?? "").trim();
    if (!outputVct) throw new Error("aura_integrity_failed");
    const domainRaw = String(row.domain ?? "");
    const domainValid = isDomainPatternValid(domainRaw);
    if (!domainValid.ok) throw new Error("aura_integrity_failed");
    const ruleLogic = parseRuleLogic(row);
    const purpose = getRulePurpose(ruleLogic);
    if (!purpose) throw new Error("aura_integrity_failed");
  }
  const ruleHash = computeAuraRuleHash(row);
  if (!row.rule_signature) {
    throw new Error("aura_integrity_failed");
  }
  await verifyAuraRuleSignature(ruleHash, row.rule_signature);
  return { ruleHash };
};

export const ensureAuraRuleIntegrity = async (row: AuraRuleRow) => {
  // Capability contract validation (fail-closed in production for enabled rules).
  if (row.enabled) {
    const outputVct = String(row.output_vct ?? "").trim();
    if (!outputVct) {
      throw new Error("aura_integrity_failed");
    }
    const domainRaw = String(row.domain ?? "");
    const domainValid = isDomainPatternValid(domainRaw);
    if (!domainValid.ok) {
      throw new Error("aura_integrity_failed");
    }
    const ruleLogic = parseRuleLogic(row);
    const purpose = getRulePurpose(ruleLogic);
    if (!purpose) {
      throw new Error("aura_integrity_failed");
    }
  }

  const ruleHash = computeAuraRuleHash(row);
  if (!row.rule_signature) {
    if (!config.POLICY_SIGNING_BOOTSTRAP) {
      throw new Error("aura_integrity_failed");
    }
    const signature = await signAuraRuleHash(ruleHash);
    const db = await getDb();
    await db("aura_rules")
      .where({ rule_id: row.rule_id })
      .update({ rule_signature: signature, updated_at: new Date().toISOString() });
    await recordAuraRuleChange(ruleHash, row);
    return { ruleHash, signature };
  }
  await verifyAuraRuleSignature(ruleHash, row.rule_signature);
  await recordAuraRuleChange(ruleHash, row);
  return { ruleHash, signature: row.rule_signature };
};
