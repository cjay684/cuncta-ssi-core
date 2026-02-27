import { decodeProtectedHeader, importJWK, jwtVerify } from "jose";
import net from "node:net";
import { z } from "zod";
import { config } from "./config.js";
import { metrics } from "./metrics.js";
import { assertEd25519Jwk } from "./crypto/jwk.js";

type CacheEntry = {
  encodedList: string;
  fetchedAt: number;
};

const statusListCache = new Map<string, CacheEntry>();
const issuerBaseUrl = new URL(config.ISSUER_SERVICE_BASE_URL);

const jwksSchema = z.object({
  keys: z.array(z.record(z.string(), z.unknown())).min(1)
});

let cachedKeys: Record<string, unknown>[] | null = null;
let cachedAt = 0;

const loadIssuerKeys = async () => {
  if (config.ISSUER_JWKS) {
    const parsed = jwksSchema.parse(JSON.parse(config.ISSUER_JWKS));
    return parsed.keys;
  }
  const now = Date.now();
  if (cachedKeys && now - cachedAt < 300_000) {
    return cachedKeys;
  }
  const response = await fetch(`${config.ISSUER_SERVICE_BASE_URL}/jwks.json`);
  if (!response.ok) {
    throw new Error("jwks_fetch_failed");
  }
  const parsed = jwksSchema.parse(await response.json());
  cachedKeys = parsed.keys;
  cachedAt = now;
  return parsed.keys;
};

const decodeBitstring = (encoded: string) => new Uint8Array(Buffer.from(encoded, "base64url"));

const isIpLiteral = (hostname: string) => {
  const candidate =
    hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const mapped = candidate.startsWith("::ffff:") ? candidate.slice(7) : candidate;
  return net.isIP(mapped) !== 0;
};

const isPrivateHostname = (hostname: string) => {
  const normalized = hostname.toLowerCase();
  if (normalized === "localhost") return true;
  const candidate =
    normalized.startsWith("[") && normalized.endsWith("]") ? normalized.slice(1, -1) : normalized;
  const mapped = candidate.startsWith("::ffff:") ? candidate.slice(7) : candidate;
  const ipType = net.isIP(mapped);
  if (ipType === 4) {
    const [a, b] = mapped.split(".").map((part) => Number(part));
    if ([a, b].some((part) => Number.isNaN(part))) return false;
    if (a === 10 || a === 127 || (a === 192 && b === 168)) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  if (ipType === 6) {
    if (candidate === "::1") return true;
    if (candidate.startsWith("fc") || candidate.startsWith("fd")) return true;
    if (
      candidate.startsWith("fe8") ||
      candidate.startsWith("fe9") ||
      candidate.startsWith("fea") ||
      candidate.startsWith("feb")
    ) {
      return true;
    }
  }
  return false;
};

const resolveStatusListUrl = (listCredential: string) => {
  let resolved: URL;
  try {
    resolved = new URL(listCredential, issuerBaseUrl);
  } catch {
    throw new Error("status_list_url_invalid");
  }
  if (resolved.origin !== issuerBaseUrl.origin) {
    throw new Error("status_list_url_invalid");
  }
  if (!resolved.pathname.startsWith("/status-lists/")) {
    throw new Error("status_list_url_invalid");
  }
  if (config.NODE_ENV === "production") {
    if (resolved.protocol !== "https:") {
      throw new Error("status_list_url_invalid");
    }
    if (isIpLiteral(resolved.hostname) || isPrivateHostname(resolved.hostname)) {
      throw new Error("status_list_url_invalid");
    }
  }
  return resolved.toString();
};

const isBitSet = (bytes: Uint8Array, index: number) => {
  const byteIndex = Math.floor(index / 8);
  const bitIndex = index % 8;
  return (bytes[byteIndex] & (1 << bitIndex)) !== 0;
};

const isCacheFresh = (entry: CacheEntry, now: number) => {
  const ttlMs = config.STATUS_LIST_CACHE_TTL_SECONDS * 1000;
  return now - entry.fetchedAt <= ttlMs;
};

const touchCacheEntry = (listUrl: string, entry: CacheEntry) => {
  statusListCache.delete(listUrl);
  statusListCache.set(listUrl, entry);
};

const setCacheEntry = (listUrl: string, entry: CacheEntry) => {
  statusListCache.delete(listUrl);
  statusListCache.set(listUrl, entry);
  const maxEntries = config.STATUS_LIST_CACHE_MAX_ENTRIES;
  while (statusListCache.size > maxEntries) {
    const oldestKey = statusListCache.keys().next().value as string | undefined;
    if (!oldestKey) break;
    statusListCache.delete(oldestKey);
  }
};

const verifyStatusListSignature = async (vc: Record<string, unknown>) => {
  const proof = vc.proof as Record<string, unknown> | undefined;
  const proofJwt = proof?.jwt as string | undefined;
  if (!proofJwt) {
    throw new Error("status_list_invalid_signature");
  }
  const keys = await loadIssuerKeys();
  const header = decodeProtectedHeader(proofJwt);
  if (header.alg !== "EdDSA") {
    throw new Error("status_list_invalid_signature");
  }
  const jwk = keys.find((key) => (key.kid ? key.kid === header.kid : true));
  if (!jwk) {
    throw new Error("status_list_invalid_signature");
  }
  try {
    const safeJwk = assertEd25519Jwk(jwk as Record<string, unknown>, "issuer");
    const key = await importJWK(safeJwk as never, header.alg);
    const { payload } = await jwtVerify(proofJwt, key);
    if (!payload || typeof payload !== "object") {
      throw new Error("status_list_invalid_signature");
    }
    return payload as Record<string, unknown>;
  } catch {
    throw new Error("status_list_invalid_signature");
  }
};

const fetchStatusList = async (listUrl: string) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), config.STATUS_LIST_FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(listUrl, { signal: controller.signal });
    if (!response.ok) {
      throw new Error("status_list_fetch_failed");
    }
    const rawVc = (await response.json()) as Record<string, unknown>;
    const verifiedVc = await verifyStatusListSignature(rawVc);
    const encodedList = (verifiedVc.credentialSubject as Record<string, unknown>)?.encodedList as
      | string
      | undefined;
    if (!encodedList) {
      throw new Error("status_list_missing");
    }
    return encodedList;
  } catch (error) {
    if (error instanceof Error && error.message === "status_list_fetch_failed") {
      throw error;
    }
    if (error instanceof Error && error.message === "status_list_missing") {
      throw error;
    }
    if (error instanceof Error && error.message === "status_list_invalid_signature") {
      throw error;
    }
    throw new Error("status_list_unavailable");
  } finally {
    clearTimeout(timeout);
  }
};

const loadEncodedList = async (listUrl: string) => {
  if (config.STATUS_LIST_STRICT_MODE) {
    metrics.incCounter("status_list_cache_miss_total");
    const encodedList = await fetchStatusList(listUrl);
    // Keep cache populated for observability/testing, but do not use it for correctness decisions
    // while strict mode is enabled.
    setCacheEntry(listUrl, { encodedList, fetchedAt: Date.now() });
    return encodedList;
  }
  const now = Date.now();
  const cached = statusListCache.get(listUrl);
  if (cached && isCacheFresh(cached, now)) {
    metrics.incCounter("status_list_cache_hit_total");
    touchCacheEntry(listUrl, cached);
    return cached.encodedList;
  }
  metrics.incCounter("status_list_cache_miss_total");
  const encodedList = await fetchStatusList(listUrl);
  setCacheEntry(listUrl, { encodedList, fetchedAt: Date.now() });
  return encodedList;
};

export const verifyStatusListEntry = async (status: Record<string, unknown>) => {
  // Backward/forward compatible parsing:
  // - Current internal shape (W3C BitstringStatusListEntry-style):
  //     { statusListCredential, statusListIndex, ... }
  // - Token-style shape (OAuth status list style):
  //     { status_list: { uri, idx } }
  // - Namespaced internal profile:
  //     { cuncta_bitstring: { statusListCredential, statusListIndex, ... } }
  const from = (value: unknown): { listCredential?: string; index?: string } => {
    if (!value || typeof value !== "object") return {};
    const v = value as Record<string, unknown>;
    const listCredential =
      typeof v.statusListCredential === "string" ? v.statusListCredential : undefined;
    const index =
      typeof v.statusListIndex === "string"
        ? v.statusListIndex
        : typeof v.statusListIndex === "number" && Number.isInteger(v.statusListIndex)
          ? String(v.statusListIndex)
          : undefined;
    return { listCredential, index };
  };

  const direct = from(status);
  const namespaced = from((status as Record<string, unknown>).cuncta_bitstring);
  const tokenStyle = (() => {
    const raw = (status as Record<string, unknown>).status_list;
    if (!raw || typeof raw !== "object") return {};
    const sl = raw as Record<string, unknown>;
    const listCredential = typeof sl.uri === "string" ? sl.uri : undefined;
    const index =
      typeof sl.idx === "string"
        ? sl.idx
        : typeof sl.idx === "number" && Number.isInteger(sl.idx)
          ? String(sl.idx)
          : undefined;
    return { listCredential, index };
  })();

  const listCredential =
    direct.listCredential ?? namespaced.listCredential ?? tokenStyle.listCredential;
  const index = direct.index ?? namespaced.index ?? tokenStyle.index;
  if (!listCredential || !index) {
    return { valid: false, reason: "missing_status_fields" };
  }
  try {
    const listUrl = resolveStatusListUrl(listCredential);
    const encodedList = await loadEncodedList(listUrl);
    const bytes = decodeBitstring(encodedList);
    const isRevoked = isBitSet(bytes, Number(index));
    return { valid: !isRevoked, reason: isRevoked ? "revoked" : undefined };
  } catch (error) {
    if (error instanceof Error) {
      if (error.message === "status_list_unavailable") {
        metrics.incCounter("status_list_unavailable_total");
      }
      return { valid: false, reason: error.message };
    }
    metrics.incCounter("status_list_unavailable_total");
    return { valid: false, reason: "status_list_unavailable" };
  }
};

export const __test__ = {
  isCacheFresh,
  setCacheEntry,
  getCacheKeys: () => Array.from(statusListCache.keys()),
  resetCache: () => statusListCache.clear()
};
