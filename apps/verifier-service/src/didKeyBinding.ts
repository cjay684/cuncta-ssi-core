import { base58btc } from "multiformats/bases/base58";

export type NormalizedEd25519Jwk = {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === "object" && !Array.isArray(value);

const decodeBase64Url = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));

const bytesEqual = (a: Uint8Array, b: Uint8Array) => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};

export const normalizeEd25519Jwk = (input: unknown): NormalizedEd25519Jwk | null => {
  if (!isRecord(input)) return null;
  const kty = input.kty;
  const crv = input.crv;
  const x = input.x;
  if (kty !== "OKP" || crv !== "Ed25519") return null;
  if (typeof x !== "string" || x.length < 32) return null;
  // Only compare public components for authorization; ignore kid/alg/use.
  return { kty: "OKP", crv: "Ed25519", x };
};

type KeyCandidate = {
  source: string;
  jwk?: NormalizedEd25519Jwk;
  publicKeyBytes?: Uint8Array;
};

const extractVerificationMethodObjects = (didDoc: Record<string, unknown>) => {
  const raw = didDoc.verificationMethod;
  if (!Array.isArray(raw)) return [] as Record<string, unknown>[];
  return raw.filter(isRecord);
};

const extractRelationshipRefs = (didDoc: Record<string, unknown>, field: string) => {
  const raw = didDoc[field];
  if (!Array.isArray(raw)) return [] as unknown[];
  return raw;
};

const toMethodId = (value: unknown): string | null => {
  if (typeof value === "string") return value;
  if (isRecord(value) && typeof value.id === "string") return value.id;
  return null;
};

const methodToCandidates = (method: Record<string, unknown>, source: string): KeyCandidate[] => {
  const candidates: KeyCandidate[] = [];
  const jwk = normalizeEd25519Jwk(method.publicKeyJwk);
  if (jwk) {
    candidates.push({ source, jwk, publicKeyBytes: decodeBase64Url(jwk.x) });
  }
  if (typeof method.publicKeyMultibase === "string") {
    try {
      let bytes = base58btc.decode(method.publicKeyMultibase);
      // Hiero DID docs may encode Ed25519 public keys as multibase(multicodec(pubkey)),
      // i.e. 0xed01 + 32-byte raw key (see "ed25519-pub" multicodec).
      if (bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) {
        bytes = bytes.slice(2);
      }
      candidates.push({ source, publicKeyBytes: bytes });
    } catch {
      // ignore invalid multibase key material
    }
  }
  return candidates;
};

export const extractAuthorizedEd25519Keys = (didDocRaw: unknown) => {
  if (!isRecord(didDocRaw)) return [] as KeyCandidate[];

  const methods = extractVerificationMethodObjects(didDocRaw);
  const methodById = new Map<string, Record<string, unknown>>();
  for (const method of methods) {
    const id = toMethodId(method);
    if (id) methodById.set(id, method);
  }

  const relationshipIds = new Set<string>();
  const embeddedMethods: Record<string, unknown>[] = [];
  for (const relationship of ["authentication", "assertionMethod"]) {
    for (const entry of extractRelationshipRefs(didDocRaw, relationship)) {
      const id = toMethodId(entry);
      if (id) relationshipIds.add(id);
      if (isRecord(entry)) {
        // Some DID docs embed verification methods directly under relationships.
        embeddedMethods.push(entry);
      }
    }
  }

  const selected: Record<string, unknown>[] = [];
  if (relationshipIds.size > 0) {
    for (const id of relationshipIds) {
      const method = methodById.get(id);
      if (method) selected.push(method);
    }
  } else {
    selected.push(...methods);
  }
  selected.push(...embeddedMethods);

  const candidates: KeyCandidate[] = [];
  for (const method of selected) {
    const id = typeof method.id === "string" ? method.id : "verificationMethod";
    candidates.push(...methodToCandidates(method, id));
  }
  return candidates;
};

export const isCnfKeyAuthorizedByDidDocument = (
  didDocument: unknown,
  cnfJwkRaw: unknown
): { ok: true } | { ok: false; reason: "cnf_invalid" | "did_key_not_authorized" } => {
  const cnfJwk = normalizeEd25519Jwk(cnfJwkRaw);
  if (!cnfJwk) return { ok: false, reason: "cnf_invalid" };
  const cnfBytes = decodeBase64Url(cnfJwk.x);

  const candidates = extractAuthorizedEd25519Keys(didDocument);
  for (const candidate of candidates) {
    if (candidate.jwk && candidate.jwk.x === cnfJwk.x) {
      return { ok: true };
    }
    if (candidate.publicKeyBytes && bytesEqual(candidate.publicKeyBytes, cnfBytes)) {
      return { ok: true };
    }
  }
  return { ok: false, reason: "did_key_not_authorized" };
};

