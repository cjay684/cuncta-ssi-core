import dotenv from "dotenv";

dotenv.config({ path: "../../.env" });

const requireEnv = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`missing_required_env:${name}`);
  return value;
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const waitFor = async <T>(
  label: string,
  conditionFn: () => Promise<{ done: boolean; value?: T; lastResponse?: unknown }>,
  opts: { timeoutMs: number; intervalMs: number }
): Promise<T> => {
  const start = Date.now();
  let lastResult: { done: boolean; value?: T; lastResponse?: unknown } = { done: false };
  while (Date.now() - start < opts.timeoutMs) {
    lastResult = await conditionFn();
    if (lastResult.done) return lastResult.value as T;
    await sleep(Math.min(opts.intervalMs, opts.timeoutMs - (Date.now() - start)));
  }
  throw new Error(
    `waitFor_timeout: ${JSON.stringify({
      label,
      elapsedMs: Date.now() - start,
      timeoutMs: opts.timeoutMs,
      lastResponse: lastResult.lastResponse ?? "no_response"
    })}`
  );
};

const fetchJson = async (
  url: string,
  init?: RequestInit
): Promise<{ ok: boolean; status: number; body: unknown }> => {
  const res = await fetch(url, init);
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { ok: res.ok, status: res.status, body };
};

const run = async () => {
  const gateway = requireEnv("APP_GATEWAY_BASE_URL").replace(/\/$/, "");
  const network = requireEnv("HEDERA_NETWORK");
  if (network !== "testnet") {
    throw new Error(`invalid_network_for_contract_e2e:${network}`);
  }

  await waitFor(
    "gateway_healthz",
    async () => {
      const result = await fetchJson(`${gateway}/healthz`);
      return { done: result.ok, lastResponse: { status: result.status, body: result.body } };
    },
    { timeoutMs: 30_000, intervalMs: 1500 }
  );
  await waitFor(
    "gateway_identity_requirements",
    async () => {
      const result = await fetchJson(`${gateway}/v1/requirements?action=identity.verify`);
      return { done: result.ok, lastResponse: { status: result.status, body: result.body } };
    },
    { timeoutMs: 30_000, intervalMs: 1500 }
  );
  await waitFor(
    "gateway_capabilities",
    async () => {
      const result = await fetchJson(`${gateway}/v1/capabilities`);
      return { done: result.ok, lastResponse: { status: result.status, body: result.body } };
    },
    { timeoutMs: 30_000, intervalMs: 1500 }
  );

  console.log("PASS contract-e2e (ssi-only)");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
