import { importJWK, jwtVerify, SignJWT, type JWK } from "jose";
import { randomUUID } from "node:crypto";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { config } from "./config.js";
import { getDb } from "./db.js";
import { writeAuditLog } from "./audit.js";

type CatalogRow = {
  vct: string;
  json_schema: unknown;
  sd_defaults: unknown;
  display: unknown;
  purpose_limits: unknown;
  presentation_templates: unknown;
  revocation_config: unknown;
  catalog_hash?: string | null;
  catalog_signature?: string | null;
};

let cachedJwk: JWK | null = null;
let cachedSigningKey: Awaited<ReturnType<typeof importJWK>> | null = null;
let cachedVerifyKey: Awaited<ReturnType<typeof importJWK>> | null = null;

const loadPolicyJwk = () => {
  if (cachedJwk) return cachedJwk;
  if (!config.POLICY_SIGNING_JWK) {
    throw new Error("catalog_integrity_failed");
  }
  let parsed: JWK;
  try {
    parsed = JSON.parse(config.POLICY_SIGNING_JWK) as JWK;
  } catch {
    throw new Error("catalog_integrity_failed");
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

export const computeCatalogHash = (row: CatalogRow) => {
  return hashCanonicalJson({
    vct: row.vct,
    json_schema: row.json_schema,
    sd_defaults: row.sd_defaults,
    display: row.display,
    purpose_limits: row.purpose_limits,
    presentation_templates: row.presentation_templates,
    revocation_config: row.revocation_config
  });
};

const signCatalogHash = async (catalogHash: string) => {
  const key = await getSigningKey();
  const jwk = loadPolicyJwk();
  return new SignJWT({ hash: catalogHash })
    .setProtectedHeader({ alg: "EdDSA", typ: "catalog-hash+jwt", kid: jwk.kid })
    .setIssuedAt()
    .sign(key);
};

const verifyCatalogSignature = async (catalogHash: string, signature: string) => {
  try {
    const key = await getVerifyKey();
    const { payload } = await jwtVerify(signature, key);
    if (!payload || typeof payload !== "object") {
      throw new Error("catalog_integrity_failed");
    }
    if (payload.hash !== catalogHash) {
      throw new Error("catalog_integrity_failed");
    }
  } catch {
    throw new Error("catalog_integrity_failed");
  }
};

const enqueueCatalogAnchor = async (catalogHash: string, row: CatalogRow) => {
  if (!config.ANCHOR_AUTH_SECRET) {
    throw new Error("anchor_auth_secret_missing");
  }
  const payloadMeta = {
    vct: row.vct,
    ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
      payloadHash: catalogHash,
      eventType: "CATALOG_CHANGE"
    })
  };
  const db = await getDb();
  await db("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: "CATALOG_CHANGE",
      payload_hash: catalogHash,
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

const recordCatalogChange = async (catalogHash: string, row: CatalogRow) => {
  const db = await getDb();
  const key = `catalog_hash:${row.vct}`;
  const existing = await db("system_metadata").where({ key }).first();
  if (existing?.value === catalogHash) {
    return;
  }
  await db("system_metadata")
    .insert({ key, value: catalogHash, updated_at: new Date().toISOString() })
    .onConflict("key")
    .merge({ value: catalogHash, updated_at: new Date().toISOString() });
  await writeAuditLog("catalog_change", {
    entityId: row.vct,
    vct: row.vct,
    catalog_hash: catalogHash
  });
  await enqueueCatalogAnchor(catalogHash, row);
};

export const ensureCatalogIntegrity = async (row: CatalogRow) => {
  const catalogHash = computeCatalogHash(row);
  if (!row.catalog_hash || !row.catalog_signature) {
    if (!config.POLICY_SIGNING_BOOTSTRAP) {
      throw new Error("catalog_integrity_failed");
    }
    const signature = await signCatalogHash(catalogHash);
    const db = await getDb();
    await db("credential_types").where({ vct: row.vct }).update({
      catalog_hash: catalogHash,
      catalog_signature: signature,
      updated_at: new Date().toISOString()
    });
    await recordCatalogChange(catalogHash, row);
    return { catalogHash, signature };
  }
  if (row.catalog_hash !== catalogHash) {
    throw new Error("catalog_integrity_failed");
  }
  await verifyCatalogSignature(catalogHash, row.catalog_signature);
  await recordCatalogChange(catalogHash, row);
  return { catalogHash, signature: row.catalog_signature };
};
