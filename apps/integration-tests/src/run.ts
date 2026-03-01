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

const resolvePayerCredentials = () => {
  const payerAccountId = (
    process.env.TESTNET_PAYER_ACCOUNT_ID ?? process.env.HEDERA_PAYER_ACCOUNT_ID
  )?.trim();
  const payerPrivateKey = (
    process.env.TESTNET_PAYER_PRIVATE_KEY ?? process.env.HEDERA_PAYER_PRIVATE_KEY
  )?.trim();
  const source = process.env.TESTNET_PAYER_ACCOUNT_ID
    ? "TESTNET_PAYER_*"
    : process.env.HEDERA_PAYER_ACCOUNT_ID
      ? "HEDERA_PAYER_*"
      : "missing";
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H2",
      location: "apps/integration-tests/src/run.ts:resolvePayerCredentials",
      message: "integration harness payer source resolution",
      data: {
        source,
        hasPayerAccountId: Boolean(payerAccountId),
        hasPayerPrivateKey: Boolean(payerPrivateKey)
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  if (!payerAccountId || !payerPrivateKey) {
    throw new Error(
      "payer_credentials_required: set TESTNET_PAYER_ACCOUNT_ID + TESTNET_PAYER_PRIVATE_KEY (or HEDERA_PAYER_*). No operator fallback in test harnesses."
    );
  }
  return { payerAccountId, payerPrivateKey };
};

const run = async () => {
  const required = [
    "APP_GATEWAY_BASE_URL",
    "ISSUER_SERVICE_BASE_URL",
    "VERIFIER_SERVICE_BASE_URL",
    "DID_SERVICE_BASE_URL"
  ];
  for (const name of required) requireEnv(name);
  const gateway = requireEnv("APP_GATEWAY_BASE_URL").replace(/\/$/, "");
  const issuer = requireEnv("ISSUER_SERVICE_BASE_URL").replace(/\/$/, "");
  const verifier = requireEnv("VERIFIER_SERVICE_BASE_URL").replace(/\/$/, "");
  const didService = requireEnv("DID_SERVICE_BASE_URL").replace(/\/$/, "");
  const network = requireEnv("HEDERA_NETWORK");
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H1",
      location: "apps/integration-tests/src/run.ts:run",
      message: "integration harness startup context",
      data: {
        network,
        gatewayHost: new URL(gateway).host,
        issuerHost: new URL(issuer).host,
        verifierHost: new URL(verifier).host,
        didServiceHost: new URL(didService).host
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  if (network !== "testnet") {
    throw new Error(`invalid_network_for_integration:${network}`);
  }
  resolvePayerCredentials();

  const waitForHealth = async (name: string, baseUrl: string) => {
    await waitFor(
      `${name}_healthz`,
      async () => {
        const result = await fetchJson(`${baseUrl}/healthz`);
        return {
          done: result.ok,
          lastResponse: { status: result.status, body: result.body }
        };
      },
      { timeoutMs: 30_000, intervalMs: 1500 }
    );
  };
  await waitForHealth("gateway", gateway);
  await waitForHealth("issuer", issuer);
  await waitForHealth("verifier", verifier);
  await waitForHealth("did_service", didService);

  await waitFor(
    "identity_requirements_ready",
    async () => {
      const result = await fetchJson(`${gateway}/v1/requirements?action=identity.verify`);
      return {
        done: result.ok,
        lastResponse: { status: result.status, body: result.body }
      };
    },
    { timeoutMs: 30_000, intervalMs: 1500 }
  );
  await waitFor(
    "issuer_metadata_ready",
    async () => {
      const result = await fetchJson(`${issuer}/.well-known/openid-credential-issuer`);
      return {
        done: result.ok,
        lastResponse: { status: result.status, body: result.body }
      };
    },
    { timeoutMs: 30_000, intervalMs: 1500 }
  );

  console.log("PASS integration-tests (ssi-only)");
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
