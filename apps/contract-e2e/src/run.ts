import dotenv from "dotenv";
import path from "node:path";
import { createHash } from "node:crypto";
import { presentSdJwtVc } from "@cuncta/sdjwt";
import { SignJWT, importJWK } from "jose";

const createIssuerAdminToken = async () => {
  const secret = process.env.SERVICE_JWT_SECRET_ISSUER ?? process.env.SERVICE_JWT_SECRET;
  const audience = process.env.SERVICE_JWT_AUDIENCE_ISSUER ?? "cuncta.service.issuer";
  if (!secret || secret.length < 32) {
    throw new Error("SERVICE_JWT_SECRET_ISSUER or SERVICE_JWT_SECRET required for issuer admin");
  }
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ scope: ["issuer:internal_issue"] })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .setAudience(audience)
    .sign(new TextEncoder().encode(secret));
};
import { hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

const repoRoot = path.resolve(process.cwd(), "..", "..");
dotenv.config({ path: path.join(repoRoot, ".env") });

const REQUIRED_ENV = [
  "APP_GATEWAY_BASE_URL",
  "ISSUER_SERVICE_BASE_URL",
  "HEDERA_NETWORK",
  "RUN_TESTNET_INTEGRATION",
  "CONTRACT_E2E_ADMIN_TOKEN",
  "SERVICE_JWT_SECRET"
];
const missing = REQUIRED_ENV.filter(
  (name) => !process.env[name] || String(process.env[name]).trim().length === 0
);
if (missing.length) {
  throw new Error(`Missing required env vars: ${missing.join(", ")}`);
}
if (process.env.RUN_TESTNET_INTEGRATION !== "1") {
  throw new Error("RUN_TESTNET_INTEGRATION must be set to 1");
}
if (process.env.HEDERA_NETWORK !== "testnet") {
  throw new Error("HEDERA_NETWORK must be set to testnet");
}

const APP_GATEWAY_BASE_URL = process.env.APP_GATEWAY_BASE_URL!;
const ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL!;
const ACTION = process.env.CONTRACT_ACTION ?? "marketplace.list_item";
const DEFAULT_VCT = process.env.CONTRACT_VCT ?? "cuncta.marketplace.seller_good_standing";
const DEVICE_ID = process.env.CONTRACT_DEVICE_ID ?? "contract-e2e-device";
const ONBOARDING_MODE = process.env.CONTRACT_ONBOARDING_MODE ?? "self-funded";
const ADMIN_TOKEN = process.env.CONTRACT_E2E_ADMIN_TOKEN!;
const HTTP_TIMEOUT_MS = Number(process.env.CONTRACT_HTTP_TIMEOUT_MS ?? 15000);
const HTTP_RETRY_MAX = Number(process.env.CONTRACT_HTTP_RETRY_MAX ?? 2);
const NONCE_EXPIRE_WAIT_MAX_MS = Number(process.env.CONTRACT_NONCE_EXPIRE_WAIT_MAX_MS ?? 180000);
const REVOKE_WAIT_MAX_MS = Number(process.env.CONTRACT_REVOKE_WAIT_MAX_MS ?? 180000);
const REVOKE_POLL_INTERVAL_MS = Number(process.env.CONTRACT_REVOKE_POLL_INTERVAL_MS ?? 5000);

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const waitFor = async <T>(
  label: string,
  conditionFn: () => Promise<{ done: boolean; value?: T; lastResponse?: unknown }>,
  opts: { timeoutMs: number; intervalMs: number }
): Promise<T> => {
  const started = Date.now();
  let last: { done: boolean; value?: T; lastResponse?: unknown } = { done: false };
  while (Date.now() - started < opts.timeoutMs) {
    last = await conditionFn();
    if (last.done) return last.value as T;
    await sleep(Math.min(opts.intervalMs, opts.timeoutMs - (Date.now() - started)));
  }
  const diagnostic = {
    label,
    elapsedMs: Date.now() - started,
    timeoutMs: opts.timeoutMs,
    lastResponse: last.lastResponse ?? "no_response"
  };
  throw new Error(`waitFor_timeout: ${JSON.stringify(diagnostic)}`);
};

const fromBase64Url = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const sha256Base64Url = (value: string) => createHash("sha256").update(value).digest("base64url");

const assertGatewayUrl = (url: URL) => {
  const base = new URL(APP_GATEWAY_BASE_URL);
  if (url.origin !== base.origin) {
    throw new Error(`Gateway-only violation: ${url.toString()}`);
  }
};

const fetchWithRetry = async (url: URL, init: RequestInit) => {
  assertGatewayUrl(url);
  let lastError: unknown;
  for (let attempt = 0; attempt <= HTTP_RETRY_MAX; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
    try {
      const response = await fetch(url, { ...init, signal: controller.signal });
      clearTimeout(timeout);
      if (response.status >= 502 && attempt < HTTP_RETRY_MAX) {
        lastError = new Error(`HTTP ${response.status}`);
        await sleep(500 * (attempt + 1));
        continue;
      }
      return response;
    } catch (error) {
      clearTimeout(timeout);
      lastError = error;
      if (attempt < HTTP_RETRY_MAX) {
        await sleep(500 * (attempt + 1));
        continue;
      }
      throw error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("request_failed");
};

const gatewayHeaders = (extra?: Record<string, string>) => ({
  "content-type": "application/json",
  "x-device-id": DEVICE_ID,
  ...(extra ?? {})
});

const adminHeaders = () => ({
  ...gatewayHeaders(),
  "x-contract-e2e-token": ADMIN_TOKEN
});

const getJsonResponse = async (response: Response) => {
  const text = await response.text();
  let json: unknown = null;
  if (response.headers.get("content-type")?.includes("application/json")) {
    try {
      json = JSON.parse(text) as unknown;
    } catch {
      json = null;
    }
  }
  return { text, json };
};

const requestJson = async <T>(url: URL, init: RequestInit) => {
  const response = await fetchWithRetry(url, init);
  const { text, json } = await getJsonResponse(response);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} ${url.toString()}: ${text}`);
  }
  return json as T;
};

type RequirementsResponse = {
  requirements: Array<{
    vct: string;
    disclosures?: string[];
    predicates?: Array<{ path: string; op: string; value?: unknown }>;
  }>;
  challenge: { nonce: string; audience: string; expires_at: string };
  binding?: { mode?: string; require?: boolean };
};

const getRequirements = async (action: string): Promise<RequirementsResponse> => {
  const url = new URL("/v1/requirements", APP_GATEWAY_BASE_URL);
  url.searchParams.set("action", action);
  return requestJson<RequirementsResponse>(url, { method: "GET", headers: gatewayHeaders() });
};

const parseHolderKeysFromEnv = async () => {
  const did = process.env.CONTRACT_TEST_DID;
  const jwkRaw = process.env.CONTRACT_TEST_HOLDER_JWK;
  if (!did && !jwkRaw) {
    return null;
  }
  if (!did || !jwkRaw) {
    throw new Error("CONTRACT_TEST_DID and CONTRACT_TEST_HOLDER_JWK must both be set");
  }
  const parsed = JSON.parse(jwkRaw) as Record<string, unknown>;
  const publicJwk = { ...parsed } as Record<string, unknown>;
  delete publicJwk.d;
  const cryptoKey = await importJWK(parsed as Record<string, unknown>, "EdDSA");
  const x = String(parsed.x ?? "");
  if (!x) {
    throw new Error("CONTRACT_TEST_HOLDER_JWK missing x");
  }
  const publicKey = fromBase64Url(x);
  return { did, jwk: parsed, publicJwk, cryptoKey, publicKey };
};

const issueCredentialViaIssuer = async (input: {
  subjectDid: string;
  vct: string;
  claims: Record<string, unknown>;
}) => {
  const token = await createIssuerAdminToken();
  const response = await fetch(new URL("/v1/admin/issue", ISSUER_SERVICE_BASE_URL), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify({
      subjectDid: input.subjectDid,
      vct: input.vct,
      claims: input.claims
    })
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`issuer admin issue failed: ${response.status} ${text}`);
  }
  return (await response.json()) as {
    credential: string;
    eventId?: string;
    credentialFingerprint?: string;
  };
};

const buildClaimsFromRequirements = (requirement: {
  predicates?: Array<{ path: string; op: string; value?: unknown }>;
}) => {
  const now = new Date().toISOString();
  const claims: Record<string, unknown> = {
    seller_good_standing: true,
    domain: "marketplace",
    as_of: now,
    tier: "silver"
  };
  for (const predicate of requirement.predicates ?? []) {
    if (predicate.op === "eq" || predicate.op === "gte" || predicate.op === "lte") {
      setByPath(claims, predicate.path, predicate.value);
    } else if (predicate.op === "in" && Array.isArray(predicate.value)) {
      setByPath(claims, predicate.path, predicate.value[0]);
    } else if (predicate.op === "exists") {
      setByPath(claims, predicate.path, true);
    }
  }
  return claims;
};

const buildDenyClaimsFromRequirements = (requirement: {
  predicates?: Array<{ path: string; op: string; value?: unknown }>;
}) => {
  const claims = buildClaimsFromRequirements(requirement);
  for (const predicate of requirement.predicates ?? []) {
    const inverted = invertPredicateValue(predicate.op, predicate.value);
    if (predicate.op === "exists") {
      deleteByPath(claims, predicate.path);
    } else if (inverted !== undefined) {
      setByPath(claims, predicate.path, inverted);
    }
  }
  return claims;
};

const setByPath = (obj: Record<string, unknown>, pathValue: string, value: unknown) => {
  const parts = pathValue.split(".");
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    const next = current[key];
    if (!next || typeof next !== "object") {
      current[key] = {};
    }
    current = current[key] as Record<string, unknown>;
  }
  current[parts[parts.length - 1]] = value;
};

const deleteByPath = (obj: Record<string, unknown>, pathValue: string) => {
  const parts = pathValue.split(".");
  let current: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    const next = current[key];
    if (!next || typeof next !== "object") {
      return;
    }
    current = next as Record<string, unknown>;
  }
  delete current[parts[parts.length - 1]];
};

const invertPredicateValue = (op: string, value?: unknown) => {
  if (op === "eq") {
    if (typeof value === "boolean") return !value;
    if (typeof value === "number") return value + 1;
    if (typeof value === "string") return `${value}-deny`;
  }
  if (op === "gte" || op === "lte") {
    if (typeof value === "number") return op === "gte" ? value - 1 : value + 1;
  }
  if (op === "in" && Array.isArray(value)) {
    const first = value[0];
    if (typeof first === "string") return `${first}-deny`;
    if (typeof first === "number") return first + 1;
  }
  return undefined;
};

const buildDisclosureList = (requirement: {
  disclosures?: string[];
  predicates?: Array<{ path: string }>;
}) => {
  const disclosures = new Set<string>(requirement.disclosures ?? []);
  for (const predicate of requirement.predicates ?? []) {
    disclosures.add(predicate.path);
  }
  return Array.from(disclosures);
};

const buildPresentation = async (input: {
  sdJwt: string;
  disclose: string[];
  nonce: string;
  audience: string;
  holderJwk: Record<string, unknown>;
  holderKey: CryptoKey;
  expOffsetSeconds?: number;
}) => {
  const sdJwtPresentation = await presentSdJwtVc({
    sdJwt: input.sdJwt,
    disclose: input.disclose
  });
  const nowSeconds = Math.floor(Date.now() / 1000);
  const kbJwt = await new SignJWT({
    aud: input.audience,
    nonce: input.nonce,
    iat: nowSeconds,
    exp: nowSeconds + (input.expOffsetSeconds ?? 120),
    sd_hash: sha256Base64Url(sdJwtPresentation),
    cnf: { jwk: input.holderJwk }
  })
    .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
    .sign(input.holderKey);
  return `${sdJwtPresentation}${kbJwt}`;
};

const mutateJwt = (value: string) => {
  for (let i = 0; i < value.length; i += 1) {
    const ch = value[i];
    if (/[A-Za-z0-9_-]/.test(ch)) {
      const replacement = ch === "a" ? "b" : "a";
      return value.slice(0, i) + replacement + value.slice(i + 1);
    }
  }
  throw new Error("failed_to_mutate_sd_jwt");
};

const verifyPresentation = async (input: {
  action: string;
  presentation: string;
  nonce: string;
  audience: string;
}) => {
  const url = new URL("/v1/verify", APP_GATEWAY_BASE_URL);
  url.searchParams.set("action", input.action);
  const response = await fetchWithRetry(url, {
    method: "POST",
    headers: gatewayHeaders(),
    body: JSON.stringify({
      presentation: input.presentation,
      nonce: input.nonce,
      audience: input.audience
    })
  });
  const { text, json } = await getJsonResponse(response);
  return { status: response.status, text, json };
};

const assertDecision = (
  label: string,
  response: { json: unknown; text?: string },
  expected: string
) => {
  if (!response.json || typeof response.json !== "object") {
    throw new Error(`${label}: response is not JSON`);
  }
  const decision = (response.json as { decision?: string }).decision;
  if (decision !== expected) {
    const body = response.text ? ` body=${response.text}` : "";
    throw new Error(`${label}: expected ${expected}, got ${decision ?? "undefined"}${body}`);
  }
};

const shapeSummary = (response: { status: number; json: unknown }) => {
  const keys =
    response.json && typeof response.json === "object" ? Object.keys(response.json).sort() : [];
  return {
    status: response.status,
    keys
  };
};

const compareShape = (
  baseline: { status: number; keys: string[] },
  next: { status: number; keys: string[] }
) => {
  const sameStatus = baseline.status === next.status;
  const sameKeys = baseline.keys.join(",") === next.keys.join(",");
  if (sameStatus && sameKeys) return;
  throw new Error(
    `shape_mismatch status:${baseline.status}=>${next.status} keys:${baseline.keys.join(
      ","
    )}=>${next.keys.join(",")}`
  );
};

const enforceOracleShape = (
  baseline: { status: number; keys: string[] },
  response: { status: number; json: unknown }
) => {
  const summary = shapeSummary(response);
  compareShape(baseline, summary);
  if (response.json && typeof response.json === "object") {
    const payload = response.json as { message?: string; reasons?: unknown };
    if (payload.reasons !== undefined) {
      throw new Error("oracle_violation: reasons present");
    }
    if (payload.message !== "Not allowed") {
      throw new Error(`oracle_violation: message=${payload.message ?? "undefined"}`);
    }
  }
};

const waitForExpiry = async (expiresAt: string) => {
  const expiryMs = Date.parse(expiresAt);
  if (Number.isNaN(expiryMs)) {
    throw new Error("invalid_expires_at");
  }
  return await waitFor(
    "nonce_expired",
    async () => {
      const now = Date.now();
      return { done: now >= expiryMs, lastResponse: { now, expiryMs, expiresAt } };
    },
    { timeoutMs: NONCE_EXPIRE_WAIT_MAX_MS, intervalMs: 1000 }
  );
};

const waitForRevocation = async (input: {
  action: string;
  sdJwt: string;
  holderJwk: Record<string, unknown>;
  holderKey: CryptoKey;
  disclose: string[];
}) => {
  await waitFor(
    "revocation_visible",
    async () => {
      const requirements = await getRequirements(input.action);
      const presentation = await buildPresentation({
        sdJwt: input.sdJwt,
        disclose: input.disclose,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience,
        holderJwk: input.holderJwk,
        holderKey: input.holderKey
      });
      const response = await verifyPresentation({
        action: input.action,
        presentation,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience
      });
      const decision =
        response.json && typeof response.json === "object"
          ? (response.json as { decision?: string }).decision
          : undefined;
      if (decision === "DENY") {
        return { done: true, lastResponse: response };
      }
      // On timeout we want enough context to see if it's "still ALLOW" vs request failure.
      const health = await fetchWithRetry(new URL("/healthz", APP_GATEWAY_BASE_URL), {
        method: "GET"
      });
      return {
        done: false,
        lastResponse: { decision, verify: response, healthStatus: health.status }
      };
    },
    { timeoutMs: REVOKE_WAIT_MAX_MS, intervalMs: REVOKE_POLL_INTERVAL_MS }
  );
};

const runTest = async (name: string, fn: () => Promise<void>) => {
  try {
    await fn();
    console.log(`PASS ${name}`);
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`FAIL ${name}: ${message}`);
    return false;
  }
};

const main = async () => {
  if (ONBOARDING_MODE === "sponsored") {
    throw new Error(
      "CONTRACT_ONBOARDING_MODE=sponsored is not supported. CUNCTA supports self-funded onboarding only. Set CONTRACT_ONBOARDING_MODE=self-funded."
    );
  }
  if (ONBOARDING_MODE !== "self-funded") {
    throw new Error("CONTRACT_ONBOARDING_MODE must be self-funded");
  }
  const holderFromEnv = await parseHolderKeysFromEnv();
  if (!holderFromEnv) {
    throw new Error(
      "Self-funded mode requires CONTRACT_TEST_DID and CONTRACT_TEST_HOLDER_JWK (pre-created DID with holder keys)."
    );
  }
  const results: boolean[] = [];
  results.push(
    await runTest("preflight gateway", async () => {
      const healthUrl = new URL("/healthz", APP_GATEWAY_BASE_URL);
      const health = await fetchWithRetry(healthUrl, { method: "GET" });
      if (!health.ok) {
        throw new Error(`healthz_unavailable status=${health.status}`);
      }
      const requirements = await getRequirements(ACTION);
      if (!requirements.challenge?.nonce || !requirements.challenge?.audience) {
        throw new Error("requirements_missing_challenge");
      }
      const revokeProbe = await fetchWithRetry(
        new URL("/v1/onboard/revoke", APP_GATEWAY_BASE_URL),
        {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify({})
        }
      );
      if (revokeProbe.status === 404 || revokeProbe.status === 403) {
        throw new Error(`revoke_unavailable status=${revokeProbe.status}`);
      }
    })
  );
  if (!results.every(Boolean)) {
    process.exit(1);
  }
  const holderKeys =
    holderFromEnv ??
    (() => {
      throw new Error("holderFromEnv required");
    })();
  const holderDid = holderFromEnv.did;

  const requirementsSeed = await getRequirements(ACTION);
  if (!requirementsSeed.requirements.length) {
    throw new Error(`requirements_empty_for_action:${ACTION}`);
  }
  if (requirementsSeed.binding?.require === false) {
    throw new Error("binding_required_in_contract_tests");
  }
  const requirement = requirementsSeed.requirements[0];
  const vct = requirement.vct ?? DEFAULT_VCT;
  const claims = buildClaimsFromRequirements(requirement);
  const denyClaims = buildDenyClaimsFromRequirements(requirement);
  const issueResult = await issueCredentialViaIssuer({ subjectDid: holderDid, vct, claims });
  const denyIssueResult = await issueCredentialViaIssuer({
    subjectDid: holderDid,
    vct,
    claims: denyClaims
  });

  const sdJwt = issueResult.credential;
  const sdJwtDeny = denyIssueResult.credential;
  const disclosureList = buildDisclosureList(requirement);

  results.push(
    await runTest("replay resistance: reuse challenge", async () => {
      const requirements = await getRequirements(ACTION);
      const presentation = await buildPresentation({
        sdJwt,
        disclose: disclosureList,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience,
        holderJwk: holderKeys.publicJwk,
        holderKey: holderKeys.cryptoKey
      });
      const first = await verifyPresentation({
        action: ACTION,
        presentation,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience
      });
      assertDecision("replay_first", first, "ALLOW");
      const second = await verifyPresentation({
        action: ACTION,
        presentation,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience
      });
      assertDecision("replay_second", second, "DENY");
    })
  );

  results.push(
    await runTest("replay resistance: reuse credential new challenge", async () => {
      const requirements = await getRequirements(ACTION);
      const presentation = await buildPresentation({
        sdJwt,
        disclose: disclosureList,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience,
        holderJwk: holderKeys.publicJwk,
        holderKey: holderKeys.cryptoKey
      });
      const response = await verifyPresentation({
        action: ACTION,
        presentation,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience
      });
      assertDecision("replay_new_challenge", response, "ALLOW");
    })
  );

  results.push(
    await runTest("replay resistance: expired challenge", async () => {
      const requirements = await getRequirements(ACTION);
      await waitForExpiry(requirements.challenge.expires_at);
      const presentation = await buildPresentation({
        sdJwt,
        disclose: disclosureList,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience,
        holderJwk: holderKeys.publicJwk,
        holderKey: holderKeys.cryptoKey
      });
      const response = await verifyPresentation({
        action: ACTION,
        presentation,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience
      });
      assertDecision("expired_challenge", response, "DENY");
    })
  );

  results.push(
    await runTest("oracle-resistant verify shape", async () => {
      const failures: Array<{
        label: string;
        response: { status: number; text: string; json: unknown };
      }> = [];

      const missingKb = await (async () => {
        const requirements = await getRequirements(ACTION);
        const presentation = await presentSdJwtVc({ sdJwt, disclose: disclosureList });
        const response = await verifyPresentation({
          action: ACTION,
          presentation,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience
        });
        return { label: "missing_kb_jwt", response };
      })();

      failures.push(missingKb);

      const wrongAudience = await (async () => {
        const requirements = await getRequirements(ACTION);
        const presentation = await buildPresentation({
          sdJwt,
          disclose: disclosureList,
          nonce: requirements.challenge.nonce,
          audience: `${requirements.challenge.audience}.wrong`,
          holderJwk: holderKeys.publicJwk,
          holderKey: holderKeys.cryptoKey
        });
        const response = await verifyPresentation({
          action: ACTION,
          presentation,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience
        });
        return { label: "wrong_audience", response };
      })();

      failures.push(wrongAudience);

      const expiredNonce = await (async () => {
        const requirements = await getRequirements(ACTION);
        await waitForExpiry(requirements.challenge.expires_at);
        const presentation = await buildPresentation({
          sdJwt,
          disclose: disclosureList,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: holderKeys.publicJwk,
          holderKey: holderKeys.cryptoKey
        });
        const response = await verifyPresentation({
          action: ACTION,
          presentation,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience
        });
        return { label: "expired_nonce", response };
      })();

      failures.push(expiredNonce);

      const invalidSdJwt = await (async () => {
        const requirements = await getRequirements(ACTION);
        const mutated = mutateJwt(sdJwt);
        const presentation = await buildPresentation({
          sdJwt: mutated,
          disclose: disclosureList,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: holderKeys.publicJwk,
          holderKey: holderKeys.cryptoKey
        });
        const response = await verifyPresentation({
          action: ACTION,
          presentation,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience
        });
        return { label: "invalid_sd_jwt_signature", response };
      })();

      failures.push(invalidSdJwt);

      const policyDeny = await (async () => {
        const requirements = await getRequirements(ACTION);
        const presentation = await buildPresentation({
          sdJwt: sdJwtDeny,
          disclose: [],
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: holderKeys.publicJwk,
          holderKey: holderKeys.cryptoKey
        });
        const response = await verifyPresentation({
          action: ACTION,
          presentation,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience
        });
        return { label: "policy_deny", response };
      })();

      failures.push(policyDeny);

      await requestJson(new URL("/v1/onboard/revoke", APP_GATEWAY_BASE_URL), {
        method: "POST",
        headers: adminHeaders(),
        body: JSON.stringify({
          credentialFingerprint: issueResult.credentialFingerprint,
          eventId: issueResult.eventId
        })
      });
      await waitForRevocation({
        action: ACTION,
        sdJwt,
        holderJwk: holderKeys.publicJwk,
        holderKey: holderKeys.cryptoKey,
        disclose: disclosureList
      });

      const revoked = await (async () => {
        const requirements = await getRequirements(ACTION);
        const presentation = await buildPresentation({
          sdJwt,
          disclose: disclosureList,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: holderKeys.publicJwk,
          holderKey: holderKeys.cryptoKey
        });
        const response = await verifyPresentation({
          action: ACTION,
          presentation,
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience
        });
        return { label: "revoked", response };
      })();

      failures.push(revoked);

      const baselineSummary = shapeSummary(failures[0].response);
      for (const failure of failures) {
        if (!failure.response.json || typeof failure.response.json !== "object") {
          throw new Error(`non_json_response:${failure.label} body=${failure.response.text}`);
        }
        assertDecision(failure.label, failure.response, "DENY");
        try {
          enforceOracleShape(baselineSummary, failure.response);
        } catch (error) {
          throw new Error(
            `${failure.label}: ${error instanceof Error ? error.message : String(error)} body=${failure.response.text}`
          );
        }
      }
    })
  );

  if (results.every(Boolean)) {
    return;
  }
  process.exitCode = 1;
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
