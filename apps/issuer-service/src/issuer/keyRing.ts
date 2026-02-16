import { exportJWK, generateKeyPair, importJWK, type JWK } from "jose";
import { randomUUID } from "node:crypto";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { getDb } from "../db.js";
import { config } from "../config.js";
import { DevFileKeyProvider, EnvJwkKeyProvider, KmsKeyProvider } from "./keyProvider.js";
import { writeAuditLog } from "../audit.js";
import { metrics } from "../metrics.js";

export type IssuerKeyRecord = {
  kid: string;
  public_jwk: JWK;
  private_jwk?: JWK | null;
  status: "ACTIVE" | "RETIRED" | "REVOKED";
};

const stripPrivateFields = (jwk: JWK) => {
  const rest = { ...jwk } as JWK;
  for (const key of ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]) {
    delete (rest as Record<string, unknown>)[key];
  }
  return rest;
};

const parseEnvJwk = (value: string) => {
  let parsed: JWK;
  try {
    parsed = JSON.parse(value) as JWK;
  } catch {
    throw new Error("issuer_jwk_invalid");
  }
  if (!parsed.kid) {
    parsed.kid = "issuer-1";
  }
  return parsed;
};

const enqueueIssuerKeyAnchor = async (
  eventType: "ISSUER_KEY_ROTATE" | "ISSUER_KEY_REVOKE",
  kid: string
) => {
  if (!config.ANCHOR_AUTH_SECRET) {
    throw new Error("anchor_auth_secret_missing");
  }
  const payloadHash = hashCanonicalJson({ kid, eventType });
  const payloadMeta = {
    kid,
    ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, { payloadHash, eventType })
  };
  const db = await getDb();
  await db("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: eventType,
      payload_hash: payloadHash,
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

const selectBootstrapKeyProvider = () => {
  if (config.ISSUER_JWK) {
    return new EnvJwkKeyProvider(config.ISSUER_JWK);
  }
  if (config.NODE_ENV === "production") {
    return new KmsKeyProvider();
  }
  return new DevFileKeyProvider();
};

const bootstrapIssuerKey = async () => {
  if (!config.ISSUER_KEYS_BOOTSTRAP) {
    throw new Error("issuer_keys_missing");
  }
  const provider = selectBootstrapKeyProvider();
  const jwk = await provider.getIssuerJwk();
  if (!jwk.kid) {
    jwk.kid = "issuer-1";
  }
  const db = await getDb();
  await db("issuer_keys")
    .insert({
      kid: jwk.kid,
      public_jwk: stripPrivateFields(jwk),
      private_jwk: config.ISSUER_KEYS_ALLOW_DB_PRIVATE ? jwk : null,
      status: "ACTIVE",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .onConflict("kid")
    .ignore();
  return jwk;
};

export const ensureIssuerKeys = async () => {
  const db = await getDb();
  const active = await db("issuer_keys").where({ status: "ACTIVE" }).first();
  if (active) return;
  await bootstrapIssuerKey();
};

export const getIssuerJwks = async () => {
  await ensureIssuerKeys();
  const db = await getDb();
  const keys = await db("issuer_keys")
    .whereIn("status", ["ACTIVE", "RETIRED"])
    .orderBy("created_at", "asc");
  return {
    keys: keys.map((row) => row.public_jwk as JWK)
  };
};

export const getActiveIssuerKey = async () => {
  await ensureIssuerKeys();
  const db = await getDb();
  const row = (await db("issuer_keys").where({ status: "ACTIVE" }).first()) as
    | IssuerKeyRecord
    | undefined;
  if (!row) {
    throw new Error("issuer_keys_missing");
  }
  let privateJwk = row.private_jwk as JWK | null | undefined;
  if (!privateJwk) {
    if (config.ISSUER_JWK) {
      const parsed = parseEnvJwk(config.ISSUER_JWK);
      if (parsed.kid === row.kid) {
        privateJwk = parsed;
      }
    }
  }
  if (!privateJwk && config.NODE_ENV !== "production") {
    const provider = selectBootstrapKeyProvider();
    const parsed = await provider.getIssuerJwk();
    if (parsed.kid === row.kid) {
      privateJwk = parsed;
    }
  }
  if (!privateJwk) {
    throw new Error("issuer_key_private_missing");
  }
  const key = await importJWK(privateJwk, "EdDSA");
  return { kid: row.kid, jwk: privateJwk, key };
};

export const rotateIssuerKey = async () => {
  if (!config.ISSUER_KEYS_ALLOW_DB_PRIVATE) {
    throw new Error("issuer_keys_private_storage_disabled");
  }
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk = await exportJWK(publicKey);
  const kid = privateJwk.kid ?? `issuer-${randomUUID()}`;
  privateJwk.kid = kid;
  publicJwk.kid = kid;

  const db = await getDb();
  await db.transaction(async (trx) => {
    await trx("issuer_keys")
      .where({ status: "ACTIVE" })
      .update({ status: "RETIRED", updated_at: new Date().toISOString() });
    await trx("issuer_keys").insert({
      kid,
      public_jwk: publicJwk,
      private_jwk: privateJwk,
      status: "ACTIVE",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
  });
  await writeAuditLog("issuer_key_rotate", { entityId: kid, kid });
  metrics.incCounter("issuer_key_rotate_total", {});
  await enqueueIssuerKeyAnchor("ISSUER_KEY_ROTATE", kid);
  return { kid };
};

export const revokeIssuerKey = async (kid: string) => {
  const db = await getDb();
  const row = await db("issuer_keys").where({ kid }).first();
  if (!row) {
    throw new Error("issuer_key_not_found");
  }
  await db("issuer_keys")
    .where({ kid })
    .update({ status: "REVOKED", updated_at: new Date().toISOString() });
  await writeAuditLog("issuer_key_revoke", { entityId: kid, kid });
  metrics.incCounter("issuer_key_revoke_total", {});
  await enqueueIssuerKeyAnchor("ISSUER_KEY_REVOKE", kid);
};
