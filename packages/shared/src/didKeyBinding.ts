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

// Minimal base58btc decoder for multibase `z...` values (no checksum).
// We keep this local to avoid pulling extra deps into shared runtime surfaces.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const base58Map = (() => {
  const map = new Map<string, number>();
  for (let i = 0; i < base58Alphabet.length; i += 1) map.set(base58Alphabet[i]!, i);
  return map;
})();

const decodeBase58btcMultibase = (value: string) => {
  if (!value.startsWith("z") || value.length < 2) {
    throw new Error("multibase_invalid");
  }
  const input = value.slice(1);
  // Big integer base conversion (base58 -> base256), little-endian byte array.
  const bytes: number[] = [0];
  for (const ch of input) {
    let carry = base58Map.get(ch);
    if (carry === undefined) throw new Error("base58_invalid");
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i]! * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading zeros in base58 are represented by leading '1's.
  let leadingZeros = 0;
  for (const ch of input) {
    if (ch === "1") leadingZeros += 1;
    else break;
  }
  const out = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0; i < bytes.length; i += 1) {
    out[out.length - 1 - i] = bytes[i]!;
  }
  return out;
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
      let bytes = decodeBase58btcMultibase(method.publicKeyMultibase);
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
