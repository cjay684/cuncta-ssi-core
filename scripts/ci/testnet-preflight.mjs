import { setTimeout as sleep } from "node:timers/promises";

const required = (key) => {
  const value = process.env[key];
  if (!value || String(value).trim().length === 0) {
    throw new Error(`missing_required_env:${key}`);
  }
  return String(value).trim();
};

const optional = (key, fallback) => {
  const value = process.env[key];
  if (!value || String(value).trim().length === 0) return fallback;
  return String(value).trim();
};

const describeEndpoint = (value) => {
  try {
    const url = new URL(value);
    const host = (url.hostname || "").toLowerCase();
    const isLoopback =
      host === "localhost" || host === "127.0.0.1" || host === "::1" || host.endsWith(".localhost");
    return {
      protocol: url.protocol.replace(":", ""),
      hasPort: Boolean(url.port),
      isLoopback
    };
  } catch {
    return { parseError: true };
  }
};

const redact = (value) => {
  if (!value) return value;
  // Very conservative: if it looks like a DER-ish private key prefix, redact.
  const s = String(value);
  if (s.startsWith("302e") || s.startsWith("3030") || s.length > 40) {
    return "[REDACTED]";
  }
  return s;
};

const fetchWithTimeout = async (url, { timeoutMs }) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("timeout"), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    const text = await res.text();
    return { status: res.status, ok: res.ok, text };
  } finally {
    clearTimeout(timeout);
  }
};

const fetchJsonWithRetry = async (url, { timeoutMs, attempts }) => {
  let last = null;
  for (let i = 0; i < attempts; i += 1) {
    try {
      const res = await fetchWithTimeout(url, { timeoutMs });
      last = res;
      if (!res.ok && res.status >= 500 && i + 1 < attempts) {
        await sleep(300 * (i + 1));
        continue;
      }
      const json = JSON.parse(res.text);
      return { ...res, json };
    } catch (err) {
      last = { status: 0, ok: false, text: err instanceof Error ? err.message : String(err) };
      if (i + 1 < attempts) {
        await sleep(300 * (i + 1));
        continue;
      }
      throw err;
    }
  }
  return { ...last, json: null };
};

const main = async () => {
  if (process.env.RUN_TESTNET_INTEGRATION !== "1") {
    throw new Error("RUN_TESTNET_INTEGRATION must be set to 1");
  }
  if (process.env.HEDERA_NETWORK !== "testnet") {
    throw new Error("HEDERA_NETWORK must be set to testnet");
  }
  const serviceJwtSecret = required("SERVICE_JWT_SECRET");
  const pseudonymizerPepper = required("PSEUDONYMIZER_PEPPER");
  const operatorAccountId = required("HEDERA_OPERATOR_ID");
  const operatorPrivateKey = required("HEDERA_OPERATOR_PRIVATE_KEY");
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H7",
      location: "scripts/ci/testnet-preflight.mjs:mainRequiredSecrets",
      message: "required secret-backed env presence validated",
      data: {
        hasServiceJwtSecret: Boolean(serviceJwtSecret),
        hasPseudonymizerPepper: Boolean(pseudonymizerPepper),
        hasOperatorAccountId: Boolean(operatorAccountId),
        hasOperatorPrivateKey: Boolean(operatorPrivateKey)
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion

  const payerAccountId =
    optional("TESTNET_PAYER_ACCOUNT_ID", null) ?? optional("HEDERA_PAYER_ACCOUNT_ID", null);
  const payerPrivateKey =
    optional("TESTNET_PAYER_PRIVATE_KEY", null) ?? optional("HEDERA_PAYER_PRIVATE_KEY", null);
  if (!payerAccountId || !payerPrivateKey) {
    throw new Error("missing_payer_credentials: set TESTNET_PAYER_* (preferred) or HEDERA_PAYER_*");
  }

  // Avoid accidental logging of secrets. We don't print values.
  console.log("[preflight] payer_account_id_present", redact(payerAccountId));
  console.log("[preflight] payer_private_key_present", redact(payerPrivateKey));

  const gatewayBaseUrl = optional("APP_GATEWAY_BASE_URL", null);
  const issuerBaseUrl = optional("ISSUER_SERVICE_BASE_URL", null);
  const verifierBaseUrl = optional("VERIFIER_SERVICE_BASE_URL", null);
  const didBaseUrl = optional("DID_SERVICE_BASE_URL", null);
  const missingServiceUrls = [
    ["APP_GATEWAY_BASE_URL", gatewayBaseUrl],
    ["ISSUER_SERVICE_BASE_URL", issuerBaseUrl],
    ["VERIFIER_SERVICE_BASE_URL", verifierBaseUrl],
    ["DID_SERVICE_BASE_URL", didBaseUrl]
  ]
    .filter(([, value]) => !value)
    .map(([key]) => key);
  // #region agent log
  fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
    body: JSON.stringify({
      sessionId: "6783de",
      runId: process.env.DEBUG_RUN_ID ?? "baseline",
      hypothesisId: "H6",
      location: "scripts/ci/testnet-preflight.mjs:main",
      message: "service URL readiness evaluated",
      data: {
        hasGatewayBaseUrl: Boolean(gatewayBaseUrl),
        hasIssuerBaseUrl: Boolean(issuerBaseUrl),
        hasVerifierBaseUrl: Boolean(verifierBaseUrl),
        hasDidBaseUrl: Boolean(didBaseUrl),
        missingServiceUrlCount: missingServiceUrls.length
      },
      timestamp: Date.now()
    })
  }).catch(() => {});
  // #endregion
  if (missingServiceUrls.length > 0) {
    throw new Error(`[preflight] missing_service_urls ${missingServiceUrls.join(",")}`);
  }

  const healthChecks = [
    ["gateway", new URL("/healthz", gatewayBaseUrl).toString()],
    ["issuer", new URL("/healthz", issuerBaseUrl).toString()],
    ["verifier", new URL("/healthz", verifierBaseUrl).toString()],
    ["did_service", new URL("/healthz", didBaseUrl).toString()]
  ];
  for (const [name, url] of healthChecks) {
    const endpointProfile = describeEndpoint(url);
    console.log(`[preflight] ${name}_endpoint_profile`, JSON.stringify(endpointProfile));
    // #region agent log
    fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
      body: JSON.stringify({
        sessionId: "6783de",
        runId: process.env.DEBUG_RUN_ID ?? "baseline",
        hypothesisId: "H10",
        location: "scripts/ci/testnet-preflight.mjs:healthCheckLoop",
        message: "health endpoint profile captured",
        data: { service: name, endpointProfile },
        timestamp: Date.now()
      })
    }).catch(() => {});
    // #endregion
    let health;
    try {
      health = await fetchWithTimeout(url, { timeoutMs: 10_000 });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      // #region agent log
      fetch("http://127.0.0.1:7699/ingest/ffc49d57-354d-40f6-8f22-e1def74475d1", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Debug-Session-Id": "6783de" },
        body: JSON.stringify({
          sessionId: "6783de",
          runId: process.env.DEBUG_RUN_ID ?? "baseline",
          hypothesisId: "H11",
          location: "scripts/ci/testnet-preflight.mjs:healthFetchCatch",
          message: "health fetch threw",
          data: { service: name, endpointProfile, error: msg },
          timestamp: Date.now()
        })
      }).catch(() => {});
      // #endregion
      throw new Error(`[preflight] ${name}_health_fetch_failed url=${url} err=${msg}`);
    }
    if (!health.ok) {
      throw new Error(
        `[preflight] ${name}_unhealthy status=${health.status} body=${health.text.slice(0, 500)}`
      );
    }
  }
  console.log("[preflight] service_health_ok");

  const mirrorUrlBase = optional("HEDERA_MIRROR_URL", "https://testnet.mirrornode.hedera.com");
  const balanceUrl = new URL("/api/v1/balances", mirrorUrlBase);
  balanceUrl.searchParams.set("account.id", payerAccountId);

  const minBalanceTinybarsRaw = optional("TESTNET_MIN_BALANCE_TINYBARS", "1000000000"); // 10 HBAR default.
  const minBalanceTinybars = Number(minBalanceTinybarsRaw);
  if (!Number.isFinite(minBalanceTinybars) || minBalanceTinybars <= 0) {
    throw new Error("invalid_TESTNET_MIN_BALANCE_TINYBARS");
  }

  const balance = await fetchJsonWithRetry(balanceUrl.toString(), {
    timeoutMs: 10_000,
    attempts: 3
  });
  if (!balance.ok) {
    throw new Error(
      `[preflight] mirror_balance_query_failed url=${balanceUrl.toString()} status=${balance.status} body=${String(
        balance.text
      ).slice(0, 500)}`
    );
  }

  const balances = Array.isArray(balance.json?.balances) ? balance.json.balances : [];
  const entry = balances.find((b) => String(b.account ?? "") === payerAccountId);
  const tinybars = Number(entry?.balance ?? NaN);
  if (!Number.isFinite(tinybars)) {
    throw new Error("[preflight] mirror_balance_parse_failed");
  }
  if (tinybars < minBalanceTinybars) {
    throw new Error(
      `[preflight] insufficient_payer_balance tinybars=${tinybars} minTinybars=${minBalanceTinybars}`
    );
  }
  console.log("[preflight] payer_balance_ok");
};

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error("[preflight] FAIL", message);
  process.exit(1);
});
