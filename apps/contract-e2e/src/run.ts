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
  try {
    const res = await fetch(url, init);
    const text = await res.text();
    let body: unknown = null;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = text;
    }
    return { ok: res.ok, status: res.status, body };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      body: {
        error: "network_error",
        message: error instanceof Error ? error.message : String(error)
      }
    };
  }
};

const run = async () => {
  const gateway = requireEnv("APP_GATEWAY_BASE_URL").replace(/\/$/, "");
  const network = requireEnv("HEDERA_NETWORK");
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H3",
      location: "apps/contract-e2e/src/run.ts:run",
      message: "contract e2e startup context",
      data: { network, gatewayHost: new URL(gateway).host },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
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
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H3",
      location: "apps/contract-e2e/src/run.ts:postHealthChecks",
      message: "contract e2e completed gateway probes only",
      data: { probed: ["healthz", "requirements", "capabilities"] },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion

  console.log("PASS contract-e2e (ssi-only)");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
