import { config } from "./config.js";

type CacheEntry = {
  didDocument: unknown;
  fetchedAt: number;
};

const cache = new Map<string, CacheEntry>();
const inflight = new Map<string, Promise<unknown>>();

const isCacheFresh = (entry: CacheEntry, now: number) =>
  now - entry.fetchedAt <= config.DID_RESOLVE_CACHE_TTL_SECONDS * 1000;

const touch = (key: string, entry: CacheEntry) => {
  cache.delete(key);
  cache.set(key, entry);
};

const setEntry = (key: string, entry: CacheEntry) => {
  cache.delete(key);
  cache.set(key, entry);
  while (cache.size > config.DID_RESOLVE_CACHE_MAX_ENTRIES) {
    const oldestKey = cache.keys().next().value as string | undefined;
    if (!oldestKey) break;
    cache.delete(oldestKey);
  }
};

export const resolveDidDocument = async (did: string): Promise<unknown> => {
  if (!config.DID_SERVICE_BASE_URL) {
    throw new Error("did_service_unconfigured");
  }
  const now = Date.now();
  const cached = cache.get(did);
  if (cached && isCacheFresh(cached, now)) {
    touch(did, cached);
    return cached.didDocument;
  }

  const existing = inflight.get(did);
  if (existing) return existing;

  const promise = (async () => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("did_resolve_timeout"), config.DID_RESOLVE_TIMEOUT_MS);
    timeout.unref?.();
    try {
      const url = new URL(`/v1/dids/resolve/${encodeURIComponent(did)}`, config.DID_SERVICE_BASE_URL);
      const response = await fetch(url, { method: "GET", signal: controller.signal });
      if (!response.ok) {
        throw new Error("did_resolve_failed");
      }
      const payload = (await response.json().catch(() => null)) as { didDocument?: unknown } | null;
      const didDocument = payload?.didDocument;
      if (!didDocument) {
        throw new Error("did_resolve_failed");
      }
      setEntry(did, { didDocument, fetchedAt: Date.now() });
      return didDocument;
    } catch (error) {
      if (controller.signal.aborted && controller.signal.reason === "did_resolve_timeout") {
        throw new Error("did_resolve_timeout");
      }
      const message = error instanceof Error ? error.message : "did_resolve_failed";
      if (message === "did_resolve_failed") throw error as Error;
      throw new Error("did_resolve_failed");
    } finally {
      clearTimeout(timeout);
      inflight.delete(did);
    }
  })();

  inflight.set(did, promise);
  return promise;
};

export const __test__ = {
  resetCache: () => {
    cache.clear();
    inflight.clear();
  },
  getCacheKeys: () => Array.from(cache.keys())
};

