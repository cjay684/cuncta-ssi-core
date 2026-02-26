export type MirrorOrder = "asc" | "desc";

export type MirrorTopicMessage = {
  consensus_timestamp: string;
  message: string; // base64
  running_hash?: string;
  running_hash_version?: number;
  sequence_number: number;
  topic_id: string;
  chunk_info?: unknown;
};

export type FetchTopicMessagesOptions = {
  sequenceNumber?: number;
  limit?: number;
  order?: MirrorOrder;
  timeoutMs?: number;
  maxAttempts?: number;
};

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const jitterMs = (ms: number) => {
  // +/- 20% jitter
  const delta = ms * 0.2;
  return Math.max(0, Math.round(ms - delta + Math.random() * (2 * delta)));
};

const backoffMs = (attempt: number, opts?: { initialMs?: number; maxMs?: number }) => {
  const initialMs = opts?.initialMs ?? 250;
  const maxMs = opts?.maxMs ?? 10_000;
  const raw = initialMs * 2 ** Math.max(0, attempt - 1);
  return Math.min(maxMs, raw);
};

const isRetryableStatus = (status: number) => status === 429 || (status >= 500 && status <= 599);

const normalizeMirrorBaseUrl = (input: string) => {
  // Accept either:
  // - https://testnet.mirrornode.hedera.com
  // - https://testnet.mirrornode.hedera.com/api/v1
  const base = new URL(input);
  const path = base.pathname.endsWith("/") ? base.pathname.slice(0, -1) : base.pathname;
  if (path.endsWith("/api/v1")) {
    return base.toString().replace(/\/$/, "");
  }
  base.pathname = `${path}/api/v1`;
  return base.toString().replace(/\/$/, "");
};

const decodeMessageBase64 = (value: string) => Buffer.from(value, "base64");

type CacheEntry<T> = { storedAt: number; value: T };
const CACHE_TTL_OK_MS = 15_000;
const CACHE_TTL_404_MS = 3_000;
const CACHE_TTL_ERROR_MS = 2_000;
const cache = new Map<string, CacheEntry<unknown>>();

const cacheGet = <T>(key: string): T | null => {
  const entry = cache.get(key);
  if (!entry) return null;
  const ttl = (entry.value as { __cache_ttl_ms?: number } | undefined)?.__cache_ttl_ms;
  const ttlMs = typeof ttl === "number" && ttl > 0 ? ttl : CACHE_TTL_OK_MS;
  if (Date.now() - entry.storedAt > ttlMs) {
    cache.delete(key);
    return null;
  }
  return entry.value as T;
};

const cacheSet = (key: string, value: unknown) => {
  cache.set(key, { storedAt: Date.now(), value });
  // Best-effort bound to avoid unbounded growth.
  if (cache.size > 500) {
    const firstKey = cache.keys().next().value as string | undefined;
    if (firstKey) cache.delete(firstKey);
  }
};

const withCacheTtl = <T extends object>(value: T, ttlMs: number) =>
  Object.assign(value, { __cache_ttl_ms: ttlMs });

const fetchJsonWithRetry = async <T>(
  url: string,
  opts: { timeoutMs: number; maxAttempts: number }
): Promise<{ ok: true; status: number; json: T } | { ok: false; status: number; error: string }> => {
  const normalizedUrl = url;
  const cached = cacheGet<
    { ok: true; status: number; json: T } | { ok: false; status: number; error: string }
  >(normalizedUrl);
  if (cached) return cached;
  for (let attempt = 1; attempt <= opts.maxAttempts; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("mirror_timeout"), opts.timeoutMs);
    timeout.unref?.();
    try {
      const res = await fetch(normalizedUrl, {
        method: "GET",
        headers: { accept: "application/json" },
        signal: controller.signal
      });
      if (res.ok) {
        const json = (await res.json().catch(() => null)) as T | null;
        if (json === null) {
          const out = withCacheTtl(
            { ok: false, status: 502, error: "mirror_invalid_json" } as const,
            CACHE_TTL_ERROR_MS
          );
          cacheSet(normalizedUrl, out);
          return out;
        }
        const out = withCacheTtl({ ok: true, status: res.status, json } as const, CACHE_TTL_OK_MS);
        cacheSet(normalizedUrl, out);
        return out;
      }
      if (!isRetryableStatus(res.status) || attempt === opts.maxAttempts) {
        const ttlMs = res.status === 404 ? CACHE_TTL_404_MS : CACHE_TTL_ERROR_MS;
        const out = withCacheTtl(
          { ok: false, status: res.status, error: `mirror_http_${res.status}` } as const,
          ttlMs
        );
        cacheSet(normalizedUrl, out);
        return out;
      }
    } catch {
      const reason = controller.signal.aborted ? "mirror_timeout" : "mirror_network_error";
      if (attempt === opts.maxAttempts) {
        const out = withCacheTtl({ ok: false, status: 0, error: reason } as const, CACHE_TTL_ERROR_MS);
        cacheSet(normalizedUrl, out);
        return out;
      }
    } finally {
      clearTimeout(timeout);
    }
    await sleep(jitterMs(backoffMs(attempt)));
  }
  return { ok: false, status: 0, error: "mirror_exhausted" };
};

export const fetchTopicMessages = async (
  mirrorBaseUrlRaw: string,
  topicId: string,
  options?: FetchTopicMessagesOptions
): Promise<
  | { ok: true; messages: MirrorTopicMessage[]; links?: { next?: string | null } }
  | { ok: false; status: number; error: string }
> => {
  const mirrorBaseUrl = normalizeMirrorBaseUrl(mirrorBaseUrlRaw);
  // Avoid `new URL("/path", "https://host/api/v1")` which would drop `/api/v1`.
  const url = new URL(`${mirrorBaseUrl}/topics/${encodeURIComponent(topicId)}/messages`);
  if (options?.sequenceNumber !== undefined) {
    // Hedera Mirror Node expects `sequencenumber` (lowercase).
    url.searchParams.set("sequencenumber", String(options.sequenceNumber));
  }
  if (options?.limit !== undefined) {
    url.searchParams.set("limit", String(options.limit));
  }
  // Be explicit; this endpoint is often used for pagination/debugging.
  url.searchParams.set("order", options?.order ?? "asc");

  const timeoutMs = options?.timeoutMs ?? 3000;
  const maxAttempts = options?.maxAttempts ?? 8;
  const res = await fetchJsonWithRetry<{ messages?: MirrorTopicMessage[]; links?: { next?: string } }>(
    url.toString(),
    { timeoutMs, maxAttempts }
  );
  if (!res.ok) return res;
  return {
    ok: true,
    messages: Array.isArray(res.json.messages) ? res.json.messages : [],
    links: res.json.links ? { next: res.json.links.next ?? null } : undefined
  };
};

export const fetchTopicMessageBySequence = async (
  mirrorBaseUrlRaw: string,
  topicId: string,
  sequenceNumber: number,
  options?: { timeoutMs?: number; maxAttempts?: number }
): Promise<
  | {
      ok: true;
      messageBytes: Uint8Array;
      sequenceNumber: number;
      consensusTimestamp: string;
      raw: MirrorTopicMessage;
    }
  | { ok: false; status: number; error: string }
> => {
  const timeoutMs = options?.timeoutMs ?? 3000;
  const maxAttempts = options?.maxAttempts ?? 8;
  // Mirror Node REST API supports filtering the messages list by `sequencenumber`,
  // but does not reliably expose a direct `/messages/{sequence}` resource across deployments.
  const list = await fetchTopicMessages(mirrorBaseUrlRaw, topicId, {
    sequenceNumber,
    limit: 1,
    order: "asc",
    timeoutMs,
    maxAttempts
  });
  if (!list.ok) return list;
  const msg = list.messages.find((m) => m.sequence_number === sequenceNumber) ?? list.messages[0];
  if (!msg || typeof msg.message !== "string") {
    return { ok: false, status: 404, error: "mirror_not_found" };
  }
  return {
    ok: true,
    messageBytes: decodeMessageBase64(msg.message),
    sequenceNumber: msg.sequence_number,
    consensusTimestamp: msg.consensus_timestamp,
    raw: msg
  };
};

