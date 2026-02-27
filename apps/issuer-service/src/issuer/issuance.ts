import { randomUUID } from "node:crypto";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { config } from "../config.js";
import { issueSdJwtVc } from "@cuncta/sdjwt";
import { SignJWT } from "jose";
import { sha256Hex } from "../crypto/sha256.js";
import { ISSUER_DID } from "./identity.js";
import { getDb } from "../db.js";
import { getCatalogEntry } from "../catalog.js";
import { writeAuditLog } from "../audit.js";
import { hashCanonicalJson, signAnchorMeta } from "@cuncta/shared";
import { getDidHashes } from "../pseudonymizer.js";
import { getPrivacyStatus } from "../privacy/restrictions.js";
import { getActiveIssuerKey } from "./keyRing.js";
import { issueDiBbsCredential } from "@cuncta/di-bbs";
import { getIssuerDiBbsKeyPair } from "../diBbs/keyPair.js";

const decodeBitstring = (bitstring: string) => new Uint8Array(Buffer.from(bitstring, "base64url"));

const encodeBitstring = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

const createBitstring = (length: number) => new Uint8Array(Math.ceil(length / 8));

const setBit = (bytes: Uint8Array, index: number, value: boolean) => {
  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;
  if (value) {
    bytes[byteIndex] |= 1 << bitIndex;
  } else {
    bytes[byteIndex] &= ~(1 << bitIndex);
  }
};

const buildStatusListVc = (
  issuerDid: string,
  listId: string,
  encodedList: string,
  statusPurpose = "revocation"
) => {
  const now = new Date().toISOString();
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/vc/status-list/2021/v1"],
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: issuerDid,
    issuanceDate: now,
    credentialSubject: {
      id: `${config.ISSUER_BASE_URL}/status-lists/${listId}`,
      type: "BitstringStatusList",
      statusPurpose,
      encodedList
    }
  };
};

const signStatusListVc = async (vc: Record<string, unknown>) => {
  const active = await getActiveIssuerKey();
  const kid = active.jwk.kid as string | undefined;
  return new SignJWT(vc)
    .setProtectedHeader({ alg: "EdDSA", typ: "status-list+jwt", ...(kid ? { kid } : {}) })
    .setIssuer(ISSUER_DID)
    .setIssuedAt()
    .sign(active.key);
};

const AjvCtor =
  (Ajv as unknown as { default?: new (...args: unknown[]) => unknown }).default ??
  (Ajv as unknown as new (...args: unknown[]) => unknown);
const addFormatsFn =
  (addFormats as unknown as { default?: (ajv: unknown) => void }).default ??
  (addFormats as unknown as (ajv: unknown) => void);

const ajv = new AjvCtor({ allErrors: true, strict: false }) as {
  compile: (schema: Record<string, unknown>) => (data: Record<string, unknown>) => boolean;
  errorsText: (errors: unknown, options: { separator: string }) => string;
  errors?: unknown;
};
addFormatsFn(ajv);

type ValidateFn = ((data: Record<string, unknown>) => boolean) & { errors?: unknown };

const validateClaims = (schema: Record<string, unknown>, claims: Record<string, unknown>) => {
  const validate = ajv.compile(schema) as ValidateFn;
  const valid = validate(claims);
  if (!valid) {
    const detail = ajv.errorsText(validate.errors ?? [], { separator: ", " });
    throw new Error(`claims_invalid: ${detail}`);
  }
};

const enqueueAnchor = async (
  trx: Awaited<ReturnType<typeof getDb>>,
  input: { eventType: string; payloadHash: string; payloadMeta: Record<string, unknown> }
) => {
  if (!config.ANCHOR_AUTH_SECRET) {
    throw new Error("anchor_auth_secret_missing");
  }
  const payloadMeta = {
    ...input.payloadMeta,
    ...signAnchorMeta(config.ANCHOR_AUTH_SECRET, {
      payloadHash: input.payloadHash,
      eventType: input.eventType
    })
  };
  await trx("anchor_outbox")
    .insert({
      outbox_id: randomUUID(),
      event_type: input.eventType,
      payload_hash: input.payloadHash,
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

const ensureStatusList = async (
  trx: Awaited<ReturnType<typeof getDb>>,
  listId: string,
  statusPurpose: string,
  bitstringSize: number
) => {
  const existing = await trx("status_lists").where({ status_list_id: listId }).forUpdate().first();
  if (existing) {
    return existing as {
      status_list_id: string;
      purpose: string;
      bitstring_size: number;
      current_version: number;
    };
  }

  const bytes = createBitstring(bitstringSize);
  const encodedList = encodeBitstring(bytes);
  await trx("status_lists")
    .insert({
      status_list_id: listId,
      purpose: statusPurpose,
      bitstring_size: bitstringSize,
      current_version: 1,
      next_index: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    })
    .onConflict("status_list_id")
    .ignore();
  await trx("status_list_versions")
    .insert({
      status_list_id: listId,
      version: 1,
      bitstring_base64: encodedList,
      published_at: new Date().toISOString()
    })
    .onConflict(["status_list_id", "version"])
    .ignore();
  const created = await trx("status_lists").where({ status_list_id: listId }).first();
  return {
    status_list_id: listId,
    purpose: statusPurpose,
    bitstring_size: bitstringSize,
    current_version: Number(created?.current_version ?? 1)
  };
};

const getCurrentStatusList = async (trx: Awaited<ReturnType<typeof getDb>>, listId: string) => {
  const list = await trx("status_lists").where({ status_list_id: listId }).first();
  if (!list) {
    throw new Error("status_list_not_found");
  }
  const version = await trx("status_list_versions")
    .where({ status_list_id: listId, version: list.current_version })
    .forUpdate()
    .first();
  if (!version) {
    throw new Error("status_list_version_missing");
  }
  return {
    list,
    version
  };
};

export const issueCredential = async (input: {
  subjectDid: string;
  claims: Record<string, unknown>;
  vct: string;
}) => {
  const catalog = await getCatalogEntry(input.vct);
  if (!catalog) {
    throw new Error("vct_not_found");
  }

  validateClaims(catalog.json_schema, input.claims);

  const hashes = getDidHashes(input.subjectDid);
  const privacyStatus = await getPrivacyStatus(hashes);
  if (privacyStatus.tombstoned) {
    throw new Error("privacy_erased");
  }

  const statusPurpose =
    (catalog.revocation_config as Record<string, unknown>).statusPurpose ?? "revocation";
  const statusListId =
    ((catalog.revocation_config as Record<string, unknown>).statusListId as string | undefined) ??
    "default";
  const bitstringSizeRaw = (catalog.revocation_config as Record<string, unknown>).bitstringSize as
    | number
    | undefined;
  const bitstringSize = Number(bitstringSizeRaw ?? config.STATUS_LIST_LENGTH);

  const db = await getDb();
  return await db.transaction(async (trx) => {
    await ensureStatusList(trx, statusListId, String(statusPurpose), bitstringSize);
    const locked = await trx("status_lists")
      .where({ status_list_id: statusListId })
      .forUpdate()
      .first();
    if (!locked) {
      throw new Error("status_list_not_found");
    }
    const nextIndex = Number(locked.next_index ?? 0);
    if (nextIndex >= bitstringSize) {
      throw new Error("status_list_full");
    }
    await trx("status_lists")
      .where({ status_list_id: statusListId })
      .update({ next_index: nextIndex + 1, updated_at: new Date().toISOString() });

    const eventId = `evt_${randomUUID()}`;
    const credentialStatus = {
      id: `${config.ISSUER_BASE_URL}/status-lists/${statusListId}#${nextIndex}`,
      type: "BitstringStatusListEntry",
      statusPurpose: String(statusPurpose),
      statusListIndex: String(nextIndex),
      statusListCredential: `${config.ISSUER_BASE_URL}/status-lists/${statusListId}`
    };

    const issuerDid = ISSUER_DID;
    const issuerJwk = (await getActiveIssuerKey()).jwk;
    const issuedAt = new Date().toISOString();
    const sdJwt = await issueSdJwtVc({
      issuerJwk: issuerJwk as never,
      payload: {
        iss: issuerDid,
        sub: input.subjectDid,
        iat: Math.floor(Date.now() / 1000),
        vct: input.vct,
        // Backward/forward compatible status encoding:
        // - Keep current W3C BitstringStatusListEntry-style fields for existing in-repo verifiers.
        // - Add token-style status_list { uri, idx } to support ecosystems that expect that shape.
        // - Add a namespaced copy so future migrations can move without ambiguity.
        status: {
          ...credentialStatus,
          status_list: {
            uri: credentialStatus.statusListCredential,
            idx: nextIndex
          },
          cuncta_bitstring: credentialStatus
        },
        ...input.claims
      },
      selectiveDisclosure: catalog.sd_defaults,
      typMode: "strict"
    });
    const subjectDidHash = hashes.primary;
    const credentialFingerprint = hashCanonicalJson({
      issuerDid,
      vct: input.vct,
      statusListId,
      statusIndex: nextIndex,
      issuedAt,
      subjectDidHash
    });

    await trx("issuance_events").insert({
      event_id: eventId,
      vct: input.vct,
      subject_did_hash: subjectDidHash,
      credential_fingerprint: credentialFingerprint,
      status_list_id: statusListId,
      status_index: nextIndex,
      issued_at: issuedAt
    });

    const issuedPayload = {
      eventId,
      vct: input.vct,
      statusListId,
      statusIndex: nextIndex,
      credentialFingerprint,
      issuedAt
    };
    const issuedPayloadHash = hashCanonicalJson(issuedPayload);
    await enqueueAnchor(trx, {
      eventType: "ISSUED",
      payloadHash: issuedPayloadHash,
      payloadMeta: {
        event_id_hash: sha256Hex(eventId),
        vct_hash: sha256Hex(input.vct),
        status_list_id_hash: sha256Hex(statusListId),
        status_index: nextIndex
      }
    });

    await writeAuditLog(
      "credential_issued",
      {
        entityId: eventId,
        vct: input.vct,
        credentialFingerprint,
        subjectDidHash
      },
      trx
    );

    return {
      eventId,
      credential: sdJwt,
      credentialFingerprint,
      credentialStatus,
      diagnostics: {
        anchorPending: true
      }
    };
  });
};

export const issueDiBbsCredentialWithStatus = async (input: {
  subjectDid: string;
  claims: Record<string, unknown>;
  vct: string;
}) => {
  const catalog = await getCatalogEntry(input.vct);
  if (!catalog) {
    throw new Error("vct_not_found");
  }
  validateClaims(catalog.json_schema, input.claims);

  const hashes = getDidHashes(input.subjectDid);
  const privacyStatus = await getPrivacyStatus(hashes);
  if (privacyStatus.tombstoned) {
    throw new Error("privacy_erased");
  }

  const statusPurpose =
    (catalog.revocation_config as Record<string, unknown>).statusPurpose ?? "revocation";
  const statusListId =
    ((catalog.revocation_config as Record<string, unknown>).statusListId as string | undefined) ??
    "default";
  const bitstringSizeRaw = (catalog.revocation_config as Record<string, unknown>).bitstringSize as
    | number
    | undefined;
  const bitstringSize = Number(bitstringSizeRaw ?? config.STATUS_LIST_LENGTH);

  const db = await getDb();
  return await db.transaction(async (trx) => {
    await ensureStatusList(trx, statusListId, String(statusPurpose), bitstringSize);
    const locked = await trx("status_lists")
      .where({ status_list_id: statusListId })
      .forUpdate()
      .first();
    if (!locked) {
      throw new Error("status_list_not_found");
    }
    const nextIndex = Number(locked.next_index ?? 0);
    if (nextIndex >= bitstringSize) {
      throw new Error("status_list_full");
    }
    await trx("status_lists")
      .where({ status_list_id: statusListId })
      .update({ next_index: nextIndex + 1, updated_at: new Date().toISOString() });

    const eventId = `evt_${randomUUID()}`;
    const credentialStatus = {
      id: `${config.ISSUER_BASE_URL}/status-lists/${statusListId}#${nextIndex}`,
      type: "BitstringStatusListEntry",
      statusPurpose: String(statusPurpose),
      statusListIndex: String(nextIndex),
      statusListCredential: `${config.ISSUER_BASE_URL}/status-lists/${statusListId}`
    };

    const keyPair = await getIssuerDiBbsKeyPair();
    const vc = await issueDiBbsCredential({
      issuer: ISSUER_DID,
      verificationMethod: `${ISSUER_DID}#bbs-key-1`,
      vct: input.vct,
      subjectClaims: input.claims,
      keyPair
    });
    const vcWithStatus = vc as Record<string, unknown> & { status?: Record<string, unknown> };
    vcWithStatus.status = {
      ...credentialStatus,
      status_list: { uri: credentialStatus.statusListCredential, idx: nextIndex },
      cuncta_bitstring: credentialStatus
    };

    const issuedAt = new Date().toISOString();
    const subjectDidHash = hashes.primary;
    const credentialFingerprint = hashCanonicalJson({
      issuerDid: ISSUER_DID,
      vct: input.vct,
      statusListId,
      statusIndex: nextIndex,
      issuedAt,
      subjectDidHash
    });

    await trx("issuance_events").insert({
      event_id: eventId,
      vct: input.vct,
      subject_did_hash: subjectDidHash,
      credential_fingerprint: credentialFingerprint,
      status_list_id: statusListId,
      status_index: nextIndex,
      issued_at: issuedAt
    });

    const issuedPayload = {
      eventId,
      vct: input.vct,
      statusListId,
      statusIndex: nextIndex,
      credentialFingerprint,
      issuedAt
    };
    const issuedPayloadHash = hashCanonicalJson(issuedPayload);
    await enqueueAnchor(trx, {
      eventType: "ISSUED",
      payloadHash: issuedPayloadHash,
      payloadMeta: {
        event_id_hash: sha256Hex(eventId),
        vct_hash: sha256Hex(input.vct),
        status_list_id_hash: sha256Hex(statusListId),
        status_index: nextIndex
      }
    });

    await writeAuditLog(
      "credential_issued",
      {
        entityId: eventId,
        vct: input.vct,
        credentialFingerprint,
        subjectDidHash
      },
      trx
    );

    return {
      eventId,
      credential: vc,
      credentialFingerprint,
      credentialStatus,
      diagnostics: { anchorPending: true }
    };
  });
};

export const revokeCredential = async (input: {
  eventId?: string;
  credentialFingerprint?: string;
  statusListId?: string;
  statusListIndex?: number;
}) => {
  const db = await getDb();
  return await db.transaction(async (trx) => {
    const record = await trx("issuance_events")
      .modify((builder) => {
        if (input.eventId) {
          builder.where({ event_id: input.eventId });
        } else if (input.credentialFingerprint) {
          builder.where({ credential_fingerprint: input.credentialFingerprint });
        } else if (input.statusListId && input.statusListIndex !== undefined) {
          builder.where({
            status_list_id: input.statusListId,
            status_index: input.statusListIndex
          });
        }
      })
      .first();
    if (!record) {
      throw new Error("issuance_event_not_found");
    }

    const { list, version } = await getCurrentStatusList(trx, record.status_list_id);
    const bitBytes = decodeBitstring(version.bitstring_base64);
    setBit(bitBytes, record.status_index, true);
    const encodedList = encodeBitstring(bitBytes);

    const nextVersion = Number(list.current_version) + 1;
    await trx("status_list_versions").insert({
      status_list_id: record.status_list_id,
      version: nextVersion,
      bitstring_base64: encodedList,
      published_at: new Date().toISOString()
    });
    await trx("status_lists").where({ status_list_id: record.status_list_id }).update({
      current_version: nextVersion,
      updated_at: new Date().toISOString()
    });

    const revokedPayload = {
      eventId: record.event_id,
      statusListId: record.status_list_id,
      statusIndex: record.status_index,
      revokedAt: new Date().toISOString()
    };
    const revokedPayloadHash = hashCanonicalJson(revokedPayload);
    await trx("status_list_versions")
      .where({ status_list_id: record.status_list_id, version: nextVersion })
      .update({ anchor_payload_hash: revokedPayloadHash });
    await enqueueAnchor(trx, {
      eventType: "REVOKED",
      payloadHash: revokedPayloadHash,
      payloadMeta: {
        event_id_hash: sha256Hex(record.event_id as string),
        status_list_id_hash: sha256Hex(record.status_list_id as string),
        status_index: record.status_index
      }
    });

    await writeAuditLog(
      "credential_revoked",
      {
        entityId: record.event_id,
        listId: record.status_list_id,
        statusListIndex: record.status_index
      },
      trx
    );

    return {
      listId: record.status_list_id,
      diagnostics: { anchorPending: true }
    };
  });
};

export const getStatusList = async (listId: string) => {
  const db = await getDb();
  const list = await db("status_lists").where({ status_list_id: listId }).first();
  if (!list) {
    throw new Error("status_list_not_found");
  }
  const version = await db("status_list_versions")
    .where({ status_list_id: listId, version: list.current_version })
    .first();
  if (!version) {
    throw new Error("status_list_version_missing");
  }
  const issuerDid = ISSUER_DID;
  const vc = buildStatusListVc(issuerDid, listId, version.bitstring_base64, list.purpose);
  const proofJwt = await signStatusListVc(vc);
  return { list, vc: { ...vc, proof: { type: "JwtProof2020", jwt: proofJwt } } };
};
