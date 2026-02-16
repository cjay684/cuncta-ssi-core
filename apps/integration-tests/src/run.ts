import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID, randomBytes } from "node:crypto";
import net from "node:net";
import { strict as assert } from "node:assert";
import { createDb, runMigrations, closeDb, type DbClient } from "@cuncta/db";
import { presentSdJwtVc } from "@cuncta/sdjwt";
import { createHmacSha256Pseudonymizer, hashCanonicalJson } from "@cuncta/shared";
import { Agent, setGlobalDispatcher } from "undici";
import { SignJWT, importJWK } from "jose";
import { base58btc } from "multiformats/bases/base58";
import { getPublicKey, sign, utils, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import * as Registrar from "@hiero-did-sdk/registrar";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

const registrarModule = Registrar as unknown as { default?: typeof Registrar };
const registrar = registrarModule.default ?? Registrar;
type RegistrarProviders = Parameters<typeof registrar.generateCreateDIDRequest>[1];

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..", "..", "..");

dotenv.config({ path: path.join(repoRoot, ".env") });

const REQUIRED_ENV = [
  "HEDERA_NETWORK",
  "HEDERA_OPERATOR_ID",
  "HEDERA_OPERATOR_PRIVATE_KEY",
  "DATABASE_URL",
  "PSEUDONYMIZER_PEPPER",
  "SERVICE_JWT_SECRET"
];
if (process.env.DYNAMIC_PORTS !== "1") {
  REQUIRED_ENV.push(
    "DID_SERVICE_BASE_URL",
    "ISSUER_SERVICE_BASE_URL",
    "VERIFIER_SERVICE_BASE_URL",
    "POLICY_SERVICE_BASE_URL"
  );
}

const GATEWAY_MODE = process.env.GATEWAY_MODE === "1";
const USER_PAYS_MODE = process.env.USER_PAYS_MODE === "1";
const NODE_ENV = process.env.NODE_ENV ?? "development";
const DEBUG_VERIFY_REASONS = process.env.GATEWAY_VERIFY_DEBUG_REASONS === "true";
const DID_WAIT_FOR_VISIBILITY = process.env.DID_WAIT_FOR_VISIBILITY !== "false";
const clampInt = (value: string | undefined, min: number, max: number, fallback: number) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.floor(parsed)));
};
const DID_VISIBILITY_TOTAL_TIMEOUT_MS = clampInt(
  process.env.DID_VISIBILITY_TOTAL_TIMEOUT_MS,
  60_000,
  1_200_000,
  1_200_000
);
const DID_RESOLVE_INTERVAL_MS = clampInt(process.env.DID_RESOLVE_INTERVAL_MS, 1000, 30_000, 5000);
const DID_RESOLVE_MAX_ATTEMPTS = clampInt(process.env.DID_RESOLVE_MAX_ATTEMPTS, 10, 1000, 240);
const DID_RESOLVE_MAX_ATTEMPTS_LIMIT = Math.max(
  1,
  Math.floor(DID_VISIBILITY_TOTAL_TIMEOUT_MS / DID_RESOLVE_INTERVAL_MS)
);
const DID_RESOLVE_ATTEMPTS = Math.min(DID_RESOLVE_MAX_ATTEMPTS, DID_RESOLVE_MAX_ATTEMPTS_LIMIT);
const DID_VISIBILITY_TIMEOUT_MS = DID_VISIBILITY_TOTAL_TIMEOUT_MS;
const DID_SERVICE_VISIBILITY_TIMEOUT_MS = Math.max(
  DID_VISIBILITY_TIMEOUT_MS,
  DID_VISIBILITY_TOTAL_TIMEOUT_MS
);
const FETCH_TIMEOUT_MS = Math.min(1_500_000, DID_VISIBILITY_TOTAL_TIMEOUT_MS + 60_000);
setGlobalDispatcher(
  new Agent({
    headersTimeout: FETCH_TIMEOUT_MS,
    bodyTimeout: FETCH_TIMEOUT_MS
  })
);
const INCLUDE_VERIFY_REASONS = !GATEWAY_MODE || DEBUG_VERIFY_REASONS;

type VerifyResponse = {
  decision: "ALLOW" | "DENY";
  reasons?: string[];
  message?: string;
};

if (GATEWAY_MODE && USER_PAYS_MODE) {
  throw new Error("GATEWAY_MODE and USER_PAYS_MODE cannot both be enabled");
}

if (USER_PAYS_MODE && (process.env.HEDERA_NETWORK !== "testnet" || NODE_ENV === "production")) {
  REQUIRED_ENV.push("HEDERA_PAYER_ACCOUNT_ID", "HEDERA_PAYER_PRIVATE_KEY");
}
if (
  USER_PAYS_MODE &&
  (process.env.HEDERA_NETWORK !== "testnet" || NODE_ENV === "production") &&
  (!process.env.HEDERA_PAYER_ACCOUNT_ID || !process.env.HEDERA_PAYER_PRIVATE_KEY)
) {
  throw new Error("operator_as_payer_disabled_in_production");
}

const missing = REQUIRED_ENV.filter(
  (name) => !process.env[name] || String(process.env[name]).trim().length === 0
);
if (missing.length) {
  throw new Error(`Missing required env vars: ${missing.join(", ")}`);
}
if (process.env.HEDERA_NETWORK !== "testnet") {
  throw new Error("HEDERA_NETWORK must be set to testnet");
}
if (process.env.ISSUER_JWKS && process.env.ISSUER_JWKS.trim().length > 0) {
  throw new Error("ISSUER_JWKS must be empty/unset for integration tests");
}

console.log(`Required env vars set: ${REQUIRED_ENV.join(", ")}`);
console.log(
  `DID visibility config: wait=${DID_WAIT_FOR_VISIBILITY} totalMs=${DID_VISIBILITY_TOTAL_TIMEOUT_MS} intervalMs=${DID_RESOLVE_INTERVAL_MS} maxAttempts=${DID_RESOLVE_ATTEMPTS} didServiceTimeoutMs=${DID_SERVICE_VISIBILITY_TIMEOUT_MS}`
);

const DATABASE_URL = process.env.DATABASE_URL!;
const SERVICE_JWT_SECRET = process.env.SERVICE_JWT_SECRET!;
const SERVICE_JWT_SECRET_DID = process.env.SERVICE_JWT_SECRET_DID ?? `${SERVICE_JWT_SECRET}-did`;
const SERVICE_JWT_SECRET_ISSUER =
  process.env.SERVICE_JWT_SECRET_ISSUER ?? `${SERVICE_JWT_SECRET}-issuer`;
const SERVICE_JWT_SECRET_VERIFIER =
  process.env.SERVICE_JWT_SECRET_VERIFIER ?? `${SERVICE_JWT_SECRET}-verifier`;
const SERVICE_JWT_AUDIENCE = process.env.SERVICE_JWT_AUDIENCE ?? "cuncta-internal";
const SERVICE_JWT_AUDIENCE_DID = process.env.SERVICE_JWT_AUDIENCE_DID ?? "cuncta.service.did";
const SERVICE_JWT_AUDIENCE_ISSUER =
  process.env.SERVICE_JWT_AUDIENCE_ISSUER ?? "cuncta.service.issuer";
const SERVICE_JWT_AUDIENCE_VERIFIER =
  process.env.SERVICE_JWT_AUDIENCE_VERIFIER ?? "cuncta.service.verifier";
const PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER!;

const DEFAULT_PORTS = {
  did: 3001,
  issuer: 3002,
  verifier: 3003,
  policy: 3004,
  gateway: 3010
};

let DID_SERVICE_BASE_URL = "";
let ISSUER_SERVICE_BASE_URL = "";
let VERIFIER_SERVICE_BASE_URL = "";
let POLICY_SERVICE_BASE_URL = "";
let ISSUER_BASE_URL = "";
let APP_GATEWAY_BASE_URL = "";
let DID_SERVICE_PORT = DEFAULT_PORTS.did;
let ISSUER_SERVICE_PORT = DEFAULT_PORTS.issuer;
let VERIFIER_SERVICE_PORT = DEFAULT_PORTS.verifier;
let POLICY_SERVICE_PORT = DEFAULT_PORTS.policy;
let APP_GATEWAY_PORT = DEFAULT_PORTS.gateway;

const isWindows = process.platform === "win32";
const nodeCmd = process.execPath;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const GATEWAY_DEVICE_ID = randomUUID();

const toBase64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const fromBase64Url = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const sha256Base64Url = (value: string) => createHash("sha256").update(value).digest("base64url");

const parsePort = (url: string, fallback: number) => {
  try {
    const parsed = new URL(url);
    if (parsed.port) return Number(parsed.port);
    return parsed.protocol === "https:" ? 443 : 80;
  } catch {
    return fallback;
  }
};

const getFreePort = () =>
  new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("Failed to allocate free port")));
        return;
      }
      const port = address.port;
      server.close(() => resolve(port));
    });
    server.on("error", (error) => reject(error));
  });

const resolveServiceUrl = async (envVar: string, portEnvVar: string, defaultPort: number) => {
  const envUrl = process.env[envVar];
  if (envUrl && envUrl.trim().length > 0) {
    return { url: envUrl, port: parsePort(envUrl, defaultPort) };
  }
  const portOverride = process.env[portEnvVar];
  const parsedPort = portOverride ? Number(portOverride) : NaN;
  const port =
    Number.isFinite(parsedPort) && parsedPort > 0
      ? parsedPort
      : process.env.DYNAMIC_PORTS === "1"
        ? await getFreePort()
        : defaultPort;
  return { url: `http://localhost:${port}`, port };
};

const resolveBaseUrls = async () => {
  const did = await resolveServiceUrl(
    "DID_SERVICE_BASE_URL",
    "DID_SERVICE_PORT",
    DEFAULT_PORTS.did
  );
  DID_SERVICE_BASE_URL = did.url;
  DID_SERVICE_PORT = did.port;

  const issuer = await resolveServiceUrl(
    "ISSUER_SERVICE_BASE_URL",
    "ISSUER_SERVICE_PORT",
    DEFAULT_PORTS.issuer
  );
  ISSUER_SERVICE_BASE_URL = issuer.url;
  ISSUER_SERVICE_PORT = issuer.port;

  const verifier = await resolveServiceUrl(
    "VERIFIER_SERVICE_BASE_URL",
    "VERIFIER_SERVICE_PORT",
    DEFAULT_PORTS.verifier
  );
  VERIFIER_SERVICE_BASE_URL = verifier.url;
  VERIFIER_SERVICE_PORT = verifier.port;

  const policy = await resolveServiceUrl(
    "POLICY_SERVICE_BASE_URL",
    "POLICY_SERVICE_PORT",
    DEFAULT_PORTS.policy
  );
  POLICY_SERVICE_BASE_URL = policy.url;
  POLICY_SERVICE_PORT = policy.port;

  const gateway = await resolveServiceUrl(
    "APP_GATEWAY_BASE_URL",
    "APP_GATEWAY_PORT",
    DEFAULT_PORTS.gateway
  );
  APP_GATEWAY_BASE_URL = gateway.url;
  APP_GATEWAY_PORT = gateway.port;

  ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? ISSUER_SERVICE_BASE_URL;
};

const createServiceToken = async (audience: string, secret: string, scope: string[] | string) => {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ scope })
    .setProtectedHeader({ alg: "HS256" })
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + 30 * 60)
    .setIssuer("app-gateway")
    .setSubject("app-gateway")
    .sign(new TextEncoder().encode(secret));
};

let warnedOperatorFallback = false;
const warnOperatorFallback = () => {
  if (warnedOperatorFallback) return;
  warnedOperatorFallback = true;
  console.warn("Using operator credentials as payer (testnet/dev only)");
};

const resolvePayerCredentials = () => {
  const payerAccountId = process.env.HEDERA_PAYER_ACCOUNT_ID?.trim();
  const payerPrivateKey = process.env.HEDERA_PAYER_PRIVATE_KEY?.trim();
  if (payerAccountId && payerPrivateKey) {
    return { payerAccountId, payerPrivateKey, usedFallback: false };
  }
  if (process.env.HEDERA_NETWORK !== "testnet" || NODE_ENV === "production") {
    throw new Error(
      "Missing HEDERA_PAYER_ACCOUNT_ID or HEDERA_PAYER_PRIVATE_KEY (required outside testnet/dev)"
    );
  }
  const operatorAccountId = process.env.HEDERA_OPERATOR_ID?.trim();
  const operatorPrivateKey = process.env.HEDERA_OPERATOR_PRIVATE_KEY?.trim();
  if (!operatorAccountId || !operatorPrivateKey) {
    throw new Error("Missing HEDERA_PAYER_* and HEDERA_OPERATOR_* for testnet/dev fallback");
  }
  warnOperatorFallback();
  return {
    payerAccountId: operatorAccountId,
    payerPrivateKey: operatorPrivateKey,
    usedFallback: true
  };
};

const ensurePolicySigningJwk = async () => {
  if (process.env.POLICY_SIGNING_JWK) {
    return process.env.POLICY_SIGNING_JWK;
  }
  const policyKeys = await generateEd25519KeyPair(`policy-${randomUUID()}`);
  return JSON.stringify(policyKeys.jwk);
};

const ensureAnchorAuthSecret = () => {
  return process.env.ANCHOR_AUTH_SECRET ?? `${randomUUID()}${randomUUID()}`;
};

const gatewayHeaders = (headers?: Record<string, string>) => ({
  ...(headers ?? {}),
  "x-device-id": GATEWAY_DEVICE_ID
});

const assertNoDirectServiceCall = (url: string) => {
  if (GATEWAY_MODE) {
    if (url.startsWith(`${DID_SERVICE_BASE_URL}/v1/dids/create/`)) {
      throw new Error(`gateway_mode_direct_did_call_blocked: ${url}`);
    }
    if (url.startsWith(`${ISSUER_SERVICE_BASE_URL}/v1/issue`)) {
      throw new Error(`gateway_mode_direct_issue_call_blocked: ${url}`);
    }
    if (url.startsWith(`${ISSUER_SERVICE_BASE_URL}/v1/internal/issue`)) {
      throw new Error(`gateway_mode_direct_internal_issue_blocked: ${url}`);
    }
  }
  if (USER_PAYS_MODE) {
    if (url.startsWith(`${DID_SERVICE_BASE_URL}/v1/dids/create/`)) {
      throw new Error(`user_pays_mode_direct_did_call_blocked: ${url}`);
    }
  }
};

const requestJson = async <T>(url: string, init?: RequestInit): Promise<T> => {
  const response = await fetch(url, init);
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`HTTP ${response.status} for ${url}: ${body}`);
  }
  return (await response.json()) as T;
};

const postJson = async <T>(url: string, payload: unknown, headers?: Record<string, string>) => {
  assertNoDirectServiceCall(url);
  return requestJson<T>(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(headers ?? {})
    },
    body: JSON.stringify(payload)
  });
};

const waitForHealth = async (url: string, timeoutMs = 120_000) => {
  const started = Date.now();
  const targets = [url];
  try {
    const parsed = new URL(url);
    if (parsed.hostname === "localhost") {
      parsed.hostname = "127.0.0.1";
      targets.push(parsed.toString());
    }
  } catch {
    // ignore
  }
  while (Date.now() - started < timeoutMs) {
    for (const target of targets) {
      try {
        const response = await fetch(target);
        if (response.ok) {
          const data = (await response.json()) as { ok?: boolean };
          if (data.ok !== false) {
            return;
          }
        }
      } catch {
        // ignore
      }
    }
    await sleep(1000);
  }
  throw new Error(`Health check timed out for ${url}`);
};

const waitForDown = async (url: string, timeoutMs = 30_000) => {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      await fetch(url);
    } catch {
      return;
    }
    await sleep(500);
  }
  throw new Error(`Service did not stop in time for ${url}`);
};

const isPortListening = (port: number, host = "127.0.0.1", timeoutMs = 500) =>
  new Promise<boolean>((resolve) => {
    const socket = net.connect({ port, host });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeoutMs);
    const finish = (listening: boolean) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(listening);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });

const assertPortsClosed = async (ports: number[]) => {
  const checks = await Promise.all(
    ports.map(async (port) => ({ port, listening: await isPortListening(port) }))
  );
  const inUse = checks.filter((entry) => entry.listening);
  if (inUse.length) {
    const details = inUse.map((entry) => String(entry.port)).join(", ");
    throw new Error(`ports_still_listening: ${details}`);
  }
};

const waitForDidResolution = async (
  did: string,
  options: { maxAttempts?: number; intervalMs?: number; totalTimeoutMs?: number } = {}
) => {
  const started = Date.now();
  const intervalMs = options.intervalMs ?? DID_RESOLVE_INTERVAL_MS;
  const totalTimeoutMs = options.totalTimeoutMs ?? DID_VISIBILITY_TOTAL_TIMEOUT_MS;
  const maxAttempts = options.maxAttempts ?? Math.max(1, Math.floor(totalTimeoutMs / intervalMs));
  const encoded = encodeURIComponent(did);
  let lastError: string | null = null;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const resolved = await requestJson<{ didDocument?: Record<string, unknown> }>(
        `${DID_SERVICE_BASE_URL}/v1/dids/resolve/${encoded}`
      );
      if (resolved?.didDocument && Object.keys(resolved.didDocument).length > 0) {
        return { elapsedMs: Date.now() - started, attempts: attempt };
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await sleep(intervalMs);
  }
  const elapsedMs = Date.now() - started;
  console.error(
    `DID visibility timeout: did=${did} elapsedMs=${elapsedMs} lastError=${lastError ?? "none"}`
  );
  throw new Error(
    `Timed out waiting for DID resolution after ${elapsedMs}ms (${maxAttempts} attempts): ${did}`
  );
};

const startService = (
  name: string,
  cwd: string,
  entry: string,
  env: NodeJS.ProcessEnv
): ChildProcess => {
  console.log(`[${name}] spawn ${nodeCmd} --import tsx ${entry}`);
  const proc = spawn(nodeCmd, ["--import", "tsx", entry], {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    shell: false
  });
  proc.stdout?.on("data", (data) => {
    process.stdout.write(`[${name}] ${data}`);
  });
  proc.stderr?.on("data", (data) => {
    process.stderr.write(`[${name}] ${data}`);
  });
  proc.on("error", (error) => {
    console.error(`[${name}] spawn error`, error);
  });
  proc.on("exit", (code, signal) => {
    if (code !== 0 || signal) {
      console.error(
        `[${name}] exited with code ${code ?? "unknown"}${signal ? ` signal=${signal}` : ""}`
      );
    }
  });
  return proc;
};

const waitForExit = (proc: ChildProcess, timeoutMs: number) =>
  new Promise<boolean>((resolve) => {
    if (proc.exitCode !== null) {
      resolve(true);
      return;
    }
    const timer = setTimeout(() => {
      proc.removeListener("exit", onExit);
      proc.removeListener("close", onExit);
      resolve(false);
    }, timeoutMs);
    const onExit = () => {
      clearTimeout(timer);
      proc.removeListener("exit", onExit);
      proc.removeListener("close", onExit);
      resolve(true);
    };
    proc.once("exit", onExit);
    proc.once("close", onExit);
  });

const stopService = async (proc: ChildProcess, name: string) => {
  if (proc.exitCode !== null) {
    console.log(`[${name}] already exited`);
    return;
  }
  proc.kill("SIGTERM");
  let exited = await waitForExit(proc, 5000);
  if (!exited) {
    proc.kill("SIGKILL");
    exited = await waitForExit(proc, 3000);
  }
  if (!exited) {
    console.warn(`[${name}] stop timed out`);
  } else {
    console.log(`[${name}] stopped`);
  }
};

const generateEd25519KeyPair = async (kid: string) => {
  const privateKey = new Uint8Array(randomBytes(32));
  const publicKey = await getPublicKey(privateKey);
  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: toBase64Url(publicKey),
    d: toBase64Url(privateKey),
    alg: "EdDSA",
    kid
  };
  const publicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x,
    alg: "EdDSA",
    kid
  };
  const cryptoKey = await importJWK(jwk, "EdDSA");
  return { privateKey, publicKey, jwk, publicJwk, cryptoKey };
};

const createDid = async (input: {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  token: string;
}) => {
  const publicKeyMultibase = base58btc.encode(input.publicKey);
  const createViaUserPays = async () => {
    const { payerAccountId, payerPrivateKey } = resolvePayerCredentials();
    const providers = {
      clientOptions: {
        network: "testnet" as unknown as string,
        accountId: payerAccountId,
        privateKey: payerPrivateKey
      }
    } as RegistrarProviders;
    const createResult = await registrar.generateCreateDIDRequest(
      {
        multibasePublicKey: publicKeyMultibase
      },
      providers
    );
    const payloadToSign = createResult.signingRequest.serializedPayload;
    const signature = await sign(payloadToSign, input.privateKey);
    const submitResult = await registrar.submitCreateDIDRequest(
      {
        state: createResult.state as Registrar.SubmitCreateDIDRequestOptions["state"],
        signature,
        waitForDIDVisibility: false,
        visibilityTimeoutMs: DID_VISIBILITY_TIMEOUT_MS
      },
      providers
    );
    return submitResult.did;
  };

  const createViaService = async () => {
    const requestUrl = GATEWAY_MODE
      ? `${APP_GATEWAY_BASE_URL}/v1/onboard/did/create/request`
      : `${DID_SERVICE_BASE_URL}/v1/dids/create/request`;
    const requestHeaders = GATEWAY_MODE
      ? gatewayHeaders()
      : { Authorization: `Bearer ${input.token}` };
    const request = await postJson<{
      state: string;
      signingRequest: { payloadToSignB64u: string; publicKeyMultibase: string };
    }>(
      requestUrl,
      {
        network: "testnet",
        publicKeyMultibase,
        options: { topicManagement: "shared", includeServiceEndpoints: false }
      },
      requestHeaders
    );
    assert.equal(request.signingRequest.publicKeyMultibase, publicKeyMultibase);
    const payloadToSign = fromBase64Url(request.signingRequest.payloadToSignB64u);
    const signature = await sign(payloadToSign, input.privateKey);
    const submitUrl = GATEWAY_MODE
      ? `${APP_GATEWAY_BASE_URL}/v1/onboard/did/create/submit`
      : `${DID_SERVICE_BASE_URL}/v1/dids/create/submit`;
    const submitHeaders = GATEWAY_MODE
      ? gatewayHeaders()
      : { Authorization: `Bearer ${input.token}` };
    const submit = await postJson<{
      did: string;
    }>(
      submitUrl,
      { state: request.state, signatureB64u: toBase64Url(signature), waitForVisibility: false },
      submitHeaders
    );
    return submit.did;
  };

  const did = USER_PAYS_MODE ? await createViaUserPays() : await createViaService();
  const resolution = await waitForDidResolution(did, {
    maxAttempts: DID_RESOLVE_ATTEMPTS,
    intervalMs: DID_RESOLVE_INTERVAL_MS,
    totalTimeoutMs: DID_VISIBILITY_TOTAL_TIMEOUT_MS
  });
  console.log(
    `did_resolution_elapsed_ms=${resolution.elapsedMs} attempts=${resolution.attempts} did=${did}`
  );
  return did;
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

const emitHealthz = async (label: string, url: string) => {
  const response = await fetch(url);
  const text = await response.text();
  console.log(`[healthz] ${label}: ${text}`);
};

const emitMetricsExcerpt = async (label: string, url: string, lines = 40) => {
  const response = await fetch(url);
  const text = await response.text();
  const excerpt = text.split("\n").slice(0, lines).join("\n");
  console.log(`[metrics] ${label} (first ${lines} lines)\n${excerpt}`);
};

const assertMetricsContains = async (label: string, url: string, metricNames: string[]) => {
  const response = await fetch(url);
  const text = await response.text();
  for (const metricName of metricNames) {
    assert.ok(text.includes(metricName), `[metrics] ${label} missing ${metricName}`);
  }
  console.log(`[metrics] ${label}: contains ${metricNames.join(", ")}`);
};

const issueCredentialFor = async (input: {
  subjectDid: string;
  vct: string;
  claims: Record<string, unknown>;
}) => {
  const issueUrl = GATEWAY_MODE
    ? `${APP_GATEWAY_BASE_URL}/v1/onboard/issue`
    : `${ISSUER_SERVICE_BASE_URL}/v1/issue`;
  const headers = GATEWAY_MODE ? gatewayHeaders() : undefined;
  return postJson<{
    credential: string;
    eventId: string;
    credentialFingerprint: string;
  }>(issueUrl, input, headers);
};

const buildTruncateSql = (tables: string[]) => {
  const quoted = tables.map((table) => `"${table.replaceAll('"', '""')}"`);
  const sql = `TRUNCATE ${quoted.join(", ")} CASCADE`;
  if (tables.length > 1) {
    assert.ok(sql.includes(", "), "truncate_sql_missing_commas");
  }
  return sql;
};

const cleanupDb = async (db: DbClient) => {
  const tables = [
    "anchor_receipts",
    "anchor_outbox",
    "issuance_events",
    "status_list_versions",
    "status_lists",
    "verification_challenges",
    "obligations_executions",
    "obligation_events",
    "aura_signals",
    "aura_state",
    "aura_issuance_queue",
    "rate_limit_events",
    "privacy_requests",
    "privacy_tokens",
    "privacy_restrictions",
    "privacy_tombstones",
    "audit_logs",
    "sponsor_budget_daily",
    "issuer_keys"
  ];
  await db.raw(buildTruncateSql(tables));
  await db("policies").update({ policy_hash: null, policy_signature: null });
  await db("credential_types").update({ catalog_hash: null, catalog_signature: null });
  await db("aura_rules").update({ rule_signature: null });
};

const waitForDbRow = async (
  db: DbClient,
  query: () => Promise<any>,
  label: string,
  timeoutMs = 120_000
) => {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const result = await query();
    if (result) {
      return result;
    }
    await sleep(2000);
  }
  throw new Error(`Timed out waiting for ${label}`);
};

const run = async () => {
  await resolveBaseUrls();
  console.log(
    `Service base URLs: did=${DID_SERVICE_BASE_URL} issuer=${ISSUER_SERVICE_BASE_URL} verifier=${VERIFIER_SERVICE_BASE_URL} policy=${POLICY_SERVICE_BASE_URL} gateway=${APP_GATEWAY_BASE_URL}`
  );
  const testRunId = randomUUID();
  const runStartedAt = new Date().toISOString();
  const serviceTokenDid = await createServiceToken(
    SERVICE_JWT_AUDIENCE_DID,
    SERVICE_JWT_SECRET_DID,
    ["did:create_request", "did:create_submit"]
  );
  const serviceTokenIssuer = await createServiceToken(
    SERVICE_JWT_AUDIENCE_ISSUER,
    SERVICE_JWT_SECRET_ISSUER,
    [
      "issuer:internal_issue",
      "issuer:revoke",
      "issuer:aura_claim",
      "issuer:reputation_ingest",
      "issuer:key_rotate",
      "issuer:key_revoke"
    ]
  );
  const db = createDb(DATABASE_URL);

  await runMigrations(db);
  await cleanupDb(db);

  const ensureMarketplacePolicy = async () => {
    const existing = await db("policies").where({ policy_id: "marketplace.list_item.v1" }).first();
    if (existing) return;
    const now = new Date().toISOString();
    const action = await db("actions").where({ action_id: "marketplace.list_item" }).first();
    if (!action) {
      await db("actions").insert({
        action_id: "marketplace.list_item",
        description: "List an item in the marketplace",
        created_at: now,
        updated_at: now
      });
    }
    const vct = "cuncta.marketplace.seller_good_standing";
    const credential = await db("credential_types").where({ vct }).first();
    if (!credential) {
      await db("credential_types").insert({
        vct,
        json_schema: JSON.stringify({
          type: "object",
          properties: {
            seller_good_standing: { type: "boolean" },
            tier: { type: "string" },
            domain: { type: "string" }
          },
          required: ["seller_good_standing", "tier", "domain"],
          additionalProperties: false
        }),
        sd_defaults: JSON.stringify([]),
        display: JSON.stringify({ title: "Seller Good Standing" }),
        purpose_limits: JSON.stringify({ actions: ["marketplace.list_item"] }),
        presentation_templates: JSON.stringify({
          required_disclosures: ["seller_good_standing", "tier"]
        }),
        revocation_config: JSON.stringify({
          statusPurpose: "revocation",
          statusListId: "default",
          bitstringSize: 2048
        }),
        created_at: now,
        updated_at: now
      });
    }
    await db("policies").insert({
      policy_id: "marketplace.list_item.v1",
      action_id: "marketplace.list_item",
      version: 1,
      enabled: true,
      logic: JSON.stringify({
        binding: { mode: "kb-jwt", require: true },
        requirements: [
          {
            vct,
            issuer: { mode: "env", env: "ISSUER_DID" },
            disclosures: ["seller_good_standing", "tier"],
            predicates: [
              { path: "seller_good_standing", op: "eq", value: true },
              { path: "domain", op: "eq", value: "marketplace" }
            ],
            revocation: { required: true }
          }
        ]
      }),
      created_at: now,
      updated_at: now
    });
  };

  await ensureMarketplacePolicy();
  await db("policies")
    .where({ action_id: "marketplace.list_item" })
    .andWhereNot({ policy_id: "marketplace.list_item.v1" })
    .del();

  const ensureDevAuraPolicy = async () => {
    const actionId = "dev.aura.signal";
    const policyId = "dev.aura.signal.v1";
    const existingAction = await db("actions").where({ action_id: actionId }).first();
    if (!existingAction) {
      await db("actions").insert({
        action_id: actionId,
        description: "Dev-only aura signal demo action",
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      });
    }
    const existingPolicy = await db("policies").where({ policy_id: policyId }).first();
    if (existingPolicy) return;
    await db("policies").insert({
      policy_id: policyId,
      action_id: actionId,
      version: 1,
      enabled: true,
      logic: JSON.stringify({
        binding: { mode: "kb-jwt", require: true },
        requirements: [
          {
            vct: "cuncta.marketplace.seller_good_standing",
            issuer: { mode: "allowlist", allowed: ["*"] },
            disclosures: ["seller_good_standing", "tier", "domain"],
            predicates: [{ path: "seller_good_standing", op: "eq", value: true }],
            revocation: { required: true }
          }
        ],
        obligations: [
          { type: "EMIT_EVENT", event: "DEV_AURA_SIGNAL", when: "ALWAYS" },
          {
            type: "AURA_SIGNAL",
            signal: "marketplace.listing_success",
            weight: 1,
            when: "ON_ALLOW"
          }
        ]
      }),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
  };

  await ensureDevAuraPolicy();

  const runAuraWorkerOnce = async () => {
    process.env.POLICY_SIGNING_JWK = process.env.POLICY_SIGNING_JWK ?? policySigningJwk;
    process.env.POLICY_SIGNING_BOOTSTRAP = "true";
    process.env.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET ?? anchorAuthSecret;
    const moduleUrl = pathToFileURL(
      path.join(repoRoot, "apps", "issuer-service", "src", "aura", "auraWorker.ts")
    ).href;
    const { processAuraSignalsOnce } = await import(moduleUrl);
    await processAuraSignalsOnce();
  };

  const ensureRequirements = async <T extends { requirements: unknown[] }>(
    action: string,
    response: T
  ): Promise<T> => {
    if (response.requirements.length > 0) return response;
    const policyRow = await db("policies")
      .where({ policy_id: `${action}.v1` })
      .first();
    if (!policyRow?.logic) return response;
    const logic = JSON.parse(policyRow.logic) as { requirements?: unknown[] };
    if (Array.isArray(logic.requirements) && logic.requirements.length > 0) {
      return { ...response, requirements: logic.requirements } as T;
    }
    return response;
  };

  const policySigningJwk = await ensurePolicySigningJwk();
  const anchorAuthSecret = ensureAnchorAuthSecret();

  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NODE_ENV: "development",
    AUTO_MIGRATE: "false",
    DEV_MODE: "true",
    ALLOW_INSECURE_DEV_AUTH: "false",
    SERVICE_JWT_SECRET,
    SERVICE_JWT_SECRET_DID,
    SERVICE_JWT_SECRET_ISSUER,
    SERVICE_JWT_SECRET_VERIFIER,
    ALLOW_LEGACY_SERVICE_JWT_SECRET: "false",
    SERVICE_JWT_AUDIENCE,
    SERVICE_JWT_AUDIENCE_DID,
    SERVICE_JWT_AUDIENCE_ISSUER,
    SERVICE_JWT_AUDIENCE_VERIFIER,
    ISSUER_SERVICE_BASE_URL,
    VERIFIER_SERVICE_BASE_URL,
    POLICY_SERVICE_BASE_URL,
    DID_SERVICE_BASE_URL,
    ISSUER_BASE_URL,
    PSEUDONYMIZER_PEPPER,
    HEDERA_NETWORK: "testnet",
    DID_WAIT_FOR_VISIBILITY: "true",
    DID_VISIBILITY_TIMEOUT_MS: String(DID_SERVICE_VISIBILITY_TIMEOUT_MS),
    HEDERA_OPERATOR_ID_DID: process.env.HEDERA_OPERATOR_ID,
    HEDERA_OPERATOR_PRIVATE_KEY_DID: process.env.HEDERA_OPERATOR_PRIVATE_KEY,
    HEDERA_OPERATOR_ID_ANCHOR: process.env.HEDERA_OPERATOR_ID,
    HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR: process.env.HEDERA_OPERATOR_PRIVATE_KEY,
    ISSUER_KEYS_BOOTSTRAP: "true",
    ISSUER_KEYS_ALLOW_DB_PRIVATE: "true",
    POLICY_SIGNING_JWK: policySigningJwk,
    POLICY_SIGNING_BOOTSTRAP: "true",
    ANCHOR_AUTH_SECRET: anchorAuthSecret
  };

  const services: Record<string, ChildProcess> = {};

  try {
    if (GATEWAY_MODE && process.env.GATEWAY_MODE_FORCE_DIRECT === "1") {
      console.log("Forced failure: attempting direct DID create in gateway mode");
      await postJson(`${DID_SERVICE_BASE_URL}/v1/dids/create/request`, {});
    }
    services.did = startService(
      "did-service",
      path.join(repoRoot, "apps", "did-service"),
      "src/index.ts",
      {
        ...baseEnv,
        PORT: String(DID_SERVICE_PORT)
      }
    );
    services.policy = startService(
      "policy-service",
      path.join(repoRoot, "apps", "policy-service"),
      "src/index.ts",
      {
        ...baseEnv,
        PORT: String(POLICY_SERVICE_PORT)
      }
    );

    await waitForHealth(`${DID_SERVICE_BASE_URL}/healthz`);
    await waitForHealth(`${POLICY_SERVICE_BASE_URL}/healthz`);

    if (!GATEWAY_MODE && !USER_PAYS_MODE) {
      const wrongScopeToken = await createServiceToken(
        SERVICE_JWT_AUDIENCE_DID,
        SERVICE_JWT_SECRET_DID,
        ["issuer:internal_issue"]
      );
      const response = await fetch(`${DID_SERVICE_BASE_URL}/v1/dids/create/request`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${wrongScopeToken}`
        },
        body: JSON.stringify({
          network: "testnet",
          publicKeyMultibase: "zBadScopeKey",
          options: { topicManagement: "shared", includeServiceEndpoints: false }
        })
      });
      const body = await response.json().catch(() => ({}));
      assert.equal(response.status, 403);
      assert.equal(body.error, "service_auth_scope_missing");
    }

    if (GATEWAY_MODE) {
      services.gateway = startService(
        "app-gateway",
        path.join(repoRoot, "apps", "app-gateway"),
        "src/index.ts",
        {
          ...baseEnv,
          DID_SERVICE_BASE_URL,
          ISSUER_SERVICE_BASE_URL,
          VERIFIER_SERVICE_BASE_URL,
          POLICY_SERVICE_BASE_URL,
          APP_GATEWAY_BASE_URL,
          PORT: String(APP_GATEWAY_PORT),
          GATEWAY_ALLOWED_VCTS: "cuncta.marketplace.seller_good_standing",
          RATE_LIMIT_IP_DEFAULT_PER_MIN: "1000",
          RATE_LIMIT_IP_DID_REQUEST_PER_MIN: "200",
          RATE_LIMIT_IP_DID_SUBMIT_PER_MIN: "200",
          RATE_LIMIT_IP_ISSUE_PER_MIN: "200",
          RATE_LIMIT_IP_VERIFY_PER_MIN: "500",
          RATE_LIMIT_DEVICE_DID_PER_DAY: "50",
          RATE_LIMIT_DEVICE_ISSUE_PER_MIN: "200",
          SPONSOR_MAX_DID_CREATES_PER_DAY: "10000",
          SPONSOR_MAX_ISSUES_PER_DAY: "10000",
          SPONSOR_KILL_SWITCH: "false"
        }
      );
      await waitForHealth(`${APP_GATEWAY_BASE_URL}/healthz`);
    }

    const issuerKeys = await generateEd25519KeyPair("issuer-1");
    const holderKeys = await generateEd25519KeyPair(`holder-${testRunId}`);

    const issuerDid = await createDid({
      publicKey: issuerKeys.publicKey,
      privateKey: issuerKeys.privateKey,
      token: serviceTokenDid
    });
    const holderDid = await createDid({
      publicKey: holderKeys.publicKey,
      privateKey: holderKeys.privateKey,
      token: serviceTokenDid
    });

    const issuerEnv = {
      ...baseEnv,
      ISSUER_DID: issuerDid,
      ISSUER_JWK: JSON.stringify(issuerKeys.jwk),
      ISSUER_INTERNAL_ALLOWED_VCTS: "cuncta.marketplace.seller_good_standing"
    };
    const verifierEnv = {
      ...baseEnv,
      ISSUER_DID: issuerDid,
      ISSUER_JWKS: "",
      STATUS_LIST_CACHE_TTL_SECONDS: process.env.STATUS_LIST_CACHE_TTL_SECONDS ?? "20"
    };

    services.issuer = startService(
      "issuer-service",
      path.join(repoRoot, "apps", "issuer-service"),
      "src/index.ts",
      {
        ...issuerEnv,
        PORT: String(ISSUER_SERVICE_PORT)
      }
    );
    services.verifier = startService(
      "verifier-service",
      path.join(repoRoot, "apps", "verifier-service"),
      "src/index.ts",
      {
        ...verifierEnv,
        PORT: String(VERIFIER_SERVICE_PORT)
      }
    );

    await waitForHealth(`${ISSUER_SERVICE_BASE_URL}/healthz`);
    await waitForHealth(`${VERIFIER_SERVICE_BASE_URL}/healthz`);

    console.log("Test 1b: Policy/catalog integrity tamper detection");
    const tamperAction = `dev.integrity.${testRunId}`;
    await db("actions").insert({
      action_id: tamperAction,
      description: "Integrity test action",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
    const tamperLogic = { binding: { mode: "kb-jwt", require: true }, requirements: [] };
    const tamperPolicyHash = hashCanonicalJson({
      policy_id: `${tamperAction}.v1`,
      action_id: tamperAction,
      version: 1,
      enabled: true,
      logic: tamperLogic
    });
    await db("policies").insert({
      policy_id: `${tamperAction}.v1`,
      action_id: tamperAction,
      version: 1,
      enabled: true,
      logic: JSON.stringify(tamperLogic),
      policy_hash: tamperPolicyHash,
      policy_signature: "bad-signature",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
    const policyResponse = await fetch(
      `${POLICY_SERVICE_BASE_URL}/v1/requirements?action=${encodeURIComponent(tamperAction)}`
    );
    assert.equal(policyResponse.status, 503);
    const policyBody = await policyResponse.json().catch(() => ({}));
    assert.equal(policyBody.error, "policy_integrity_failed");

    const tamperVct = `cuncta.integrity.${testRunId}`;
    await db("credential_types").insert({
      vct: tamperVct,
      json_schema: JSON.stringify({ type: "object", properties: {}, additionalProperties: false }),
      sd_defaults: JSON.stringify([]),
      display: JSON.stringify({ title: "Integrity Test" }),
      purpose_limits: JSON.stringify({ actions: [] }),
      presentation_templates: JSON.stringify({}),
      revocation_config: JSON.stringify({ statusPurpose: "revocation", statusListId: "default" }),
      catalog_hash: "bad-hash",
      catalog_signature: "bad-signature",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });
    const catalogResponse = await fetch(
      `${ISSUER_SERVICE_BASE_URL}/v1/catalog/credentials/${encodeURIComponent(tamperVct)}`
    );
    assert.equal(catalogResponse.status, 503);
    const catalogBody = await catalogResponse.json().catch(() => ({}));
    assert.equal(catalogBody.error, "catalog_integrity_failed");
    await db("policies")
      .where({ policy_id: `${tamperAction}.v1` })
      .del();
    await db("actions").where({ action_id: tamperAction }).del();
    await db("credential_types").where({ vct: tamperVct }).del();

    console.log("Test 1a: Issuer key rotation + revoke");
    const jwksBefore = await requestJson<{ keys: Array<{ kid?: string }> }>(
      `${ISSUER_SERVICE_BASE_URL}/jwks.json`
    );
    const oldKid = jwksBefore.keys[0]?.kid;
    assert.ok(oldKid, "expected initial issuer kid");
    const fetchRotationRequirements = () =>
      requestJson<{
        challenge: { nonce: string; audience: string };
        requirements: Array<{
          vct: string;
          disclosures?: string[];
          predicates?: Array<{ path: string; op: string; value?: unknown }>;
        }>;
      }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    let rotationRequirements = await fetchRotationRequirements();
    for (
      let attempt = 0;
      attempt < 5 && rotationRequirements.requirements.length === 0;
      attempt++
    ) {
      await sleep(2000);
      rotationRequirements = await fetchRotationRequirements();
    }
    if (rotationRequirements.requirements.length === 0) {
      await stopService(services.policy, "policy-service");
      await waitForDown(`${POLICY_SERVICE_BASE_URL}/healthz`);
      services.policy = startService(
        "policy-service",
        path.join(repoRoot, "apps", "policy-service"),
        "src/index.ts",
        {
          ...baseEnv,
          PORT: String(POLICY_SERVICE_PORT)
        }
      );
      await waitForHealth(`${POLICY_SERVICE_BASE_URL}/healthz`);
      for (
        let attempt = 0;
        attempt < 5 && rotationRequirements.requirements.length === 0;
        attempt++
      ) {
        await sleep(2000);
        rotationRequirements = await fetchRotationRequirements();
      }
    }
    const rotationReq = rotationRequirements.requirements[0];
    assert.ok(rotationReq, "expected rotation requirements");
    const preRotation = await issueCredentialFor({
      subjectDid: holderDid,
      vct: rotationReq.vct,
      claims: buildClaimsFromRequirements(rotationReq)
    });
    const rotationPresentation = await buildPresentation({
      sdJwt: preRotation.credential,
      disclose: buildDisclosureList(rotationReq),
      nonce: rotationRequirements.challenge.nonce,
      audience: rotationRequirements.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const rotateResponse = await postJson<{ ok: boolean; kid: string }>(
      `${ISSUER_SERVICE_BASE_URL}/v1/internal/keys/rotate`,
      {},
      { Authorization: `Bearer ${serviceTokenIssuer}` }
    );
    assert.ok(rotateResponse.kid);
    const jwksAfterRotate = await requestJson<{ keys: Array<{ kid?: string }> }>(
      `${ISSUER_SERVICE_BASE_URL}/jwks.json`
    );
    const afterKids = jwksAfterRotate.keys.map((key) => key.kid).filter(Boolean);
    assert.ok(afterKids.includes(oldKid));
    assert.ok(afterKids.includes(rotateResponse.kid));
    const verifyBaseUrlRotation = GATEWAY_MODE ? APP_GATEWAY_BASE_URL : VERIFIER_SERVICE_BASE_URL;
    const verifyRotation = await postJson<{ decision: string }>(
      `${verifyBaseUrlRotation}/v1/verify?action=marketplace.list_item`,
      {
        presentation: rotationPresentation,
        nonce: rotationRequirements.challenge.nonce,
        audience: rotationRequirements.challenge.audience
      }
    );
    assert.equal(verifyRotation.decision, "ALLOW");
    await postJson(
      `${ISSUER_SERVICE_BASE_URL}/v1/internal/keys/revoke`,
      { kid: oldKid },
      { Authorization: `Bearer ${serviceTokenIssuer}` }
    );
    const jwksAfterRevoke = await requestJson<{ keys: Array<{ kid?: string }> }>(
      `${ISSUER_SERVICE_BASE_URL}/jwks.json`
    );
    const revokeKids = jwksAfterRevoke.keys.map((key) => key.kid).filter(Boolean);
    assert.ok(!revokeKids.includes(oldKid));

    console.log("Test 1: DID creation + resolution");
    const resolved = await requestJson<{ didDocument: Record<string, unknown> }>(
      `${DID_SERVICE_BASE_URL}/v1/dids/resolve/${encodeURIComponent(holderDid)}`
    );
    assert.ok(resolved.didDocument);

    console.log("Test 2: Issue -> requirements -> verify (ALLOW)");
    let requirements = await requestJson<{
      challenge: { nonce: string; audience: string };
      requirements: Array<{
        vct: string;
        disclosures?: string[];
        predicates?: Array<{ path: string; op: string; value?: unknown }>;
      }>;
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    requirements = await ensureRequirements("marketplace.list_item", requirements);
    const requirement = requirements.requirements[0];
    assert.ok(requirement);
    const issueResponse = await issueCredentialFor({
      subjectDid: holderDid,
      vct: requirement.vct,
      claims: buildClaimsFromRequirements(requirement)
    });
    const disclosureList = buildDisclosureList(requirement);
    const presentation = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: requirements.challenge.nonce,
      audience: requirements.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const verifyBaseUrl = GATEWAY_MODE ? APP_GATEWAY_BASE_URL : VERIFIER_SERVICE_BASE_URL;
    const verifyAllow = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation,
        nonce: requirements.challenge.nonce,
        audience: requirements.challenge.audience
      }
    );
    assert.equal(verifyAllow.decision, "ALLOW");

    console.log("Test 2a: Missing KB-JWT always DENY");
    const sdJwtPresentation = await presentSdJwtVc({
      sdJwt: issueResponse.credential,
      disclose: disclosureList
    });
    const missingKbRequirements = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const verifyMissingKbJwt = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: sdJwtPresentation,
        nonce: missingKbRequirements.challenge.nonce,
        audience: missingKbRequirements.challenge.audience
      }
    );
    assert.equal(verifyMissingKbJwt.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(verifyMissingKbJwt.reasons?.includes("kb_jwt_missing"));
    }

    console.log("Test 2b: Oversized presentation rejected");
    const oversizedRequirements = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const oversizedPresentation = "a".repeat(80000);
    const oversizedResponse = await fetch(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          presentation: oversizedPresentation,
          nonce: oversizedRequirements.challenge.nonce,
          audience: oversizedRequirements.challenge.audience
        })
      }
    );
    if (GATEWAY_MODE) {
      if (oversizedResponse.ok) {
        const payload = (await oversizedResponse.json().catch(() => ({}))) as VerifyResponse;
        assert.equal(payload.decision, "DENY");
      } else {
        assert.ok([400, 413].includes(oversizedResponse.status));
      }
    } else {
      if (![400, 413].includes(oversizedResponse.status)) {
        const bodyText = await oversizedResponse.text().catch(() => "");
        console.log(
          `Oversized presentation response status=${oversizedResponse.status} body=${bodyText.slice(0, 200)}`
        );
      }
      assert.ok([400, 413].includes(oversizedResponse.status));
    }

    console.log("Test 2c: Too many disclosures rejected");
    const disclosuresRequirements = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const tooManyDisclosures = Array.from({ length: 101 }, (_, i) => `d${i}`).join("~");
    const tooManyPresentation = `${sdJwtPresentation}${tooManyDisclosures}~dummy-kbjwt`;
    const tooManyResponse = await fetch(`${verifyBaseUrl}/v1/verify?action=marketplace.list_item`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        presentation: tooManyPresentation,
        nonce: disclosuresRequirements.challenge.nonce,
        audience: disclosuresRequirements.challenge.audience
      })
    });
    if (GATEWAY_MODE) {
      const payload = (await tooManyResponse.json().catch(() => ({}))) as VerifyResponse;
      assert.equal(payload.decision, "DENY");
    } else {
      assert.equal(tooManyResponse.status, 400);
    }

    console.log("Test 3: Revoke -> verify (DENY revoked)");
    await postJson(
      `${ISSUER_SERVICE_BASE_URL}/v1/credentials/revoke`,
      { eventId: issueResponse.eventId },
      { Authorization: `Bearer ${serviceTokenIssuer}` }
    );
    let verifyRevoked: VerifyResponse | undefined;
    const revokeStartedAt = Date.now();
    let revokeCheckAttempt = 0;
    while (Date.now() - revokeStartedAt < 180_000) {
      let requirementsAfterRevoke = await requestJson<{
        challenge: { nonce: string; audience: string };
        requirements: Array<{
          vct: string;
          disclosures?: string[];
          predicates?: Array<{ path: string; op: string; value?: unknown }>;
        }>;
      }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
      requirementsAfterRevoke = await ensureRequirements(
        "marketplace.list_item",
        requirementsAfterRevoke
      );
      const presentationAfterRevoke = await buildPresentation({
        sdJwt: issueResponse.credential,
        disclose: disclosureList,
        nonce: requirementsAfterRevoke.challenge.nonce,
        audience: requirementsAfterRevoke.challenge.audience,
        holderJwk: holderKeys.publicJwk,
        holderKey: holderKeys.cryptoKey
      });
      verifyRevoked = await postJson<VerifyResponse>(
        `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
        {
          presentation: presentationAfterRevoke,
          nonce: requirementsAfterRevoke.challenge.nonce,
          audience: requirementsAfterRevoke.challenge.audience
        }
      );
      revokeCheckAttempt += 1;
      if (revokeCheckAttempt % 3 === 0) {
        const reasons = verifyRevoked.reasons?.join(",") ?? "";
        console.log(
          `Revocation check (${revokeCheckAttempt}): ${verifyRevoked.decision} ${reasons}`
        );
      }
      if (
        verifyRevoked.decision === "DENY" &&
        (INCLUDE_VERIFY_REASONS ? verifyRevoked.reasons?.includes("revoked") : true)
      ) {
        break;
      }
      await sleep(5000);
    }
    assert.ok(verifyRevoked);
    assert.equal(verifyRevoked.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(verifyRevoked.reasons?.includes("revoked"));
    }

    const auraIssueResponse = await issueCredentialFor({
      subjectDid: holderDid,
      vct: requirement.vct,
      claims: buildClaimsFromRequirements(requirement)
    });
    const auraCredential = auraIssueResponse.credential;

    console.log("Test 4: Aura signal + claim (DEV_MODE)");
    let devRequirements = await requestJson<{
      challenge: { nonce: string; audience: string };
      requirements: Array<{
        vct: string;
        disclosures?: string[];
        predicates?: Array<{ path: string; op: string; value?: unknown }>;
      }>;
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=dev.aura.signal`);
    devRequirements = await ensureRequirements("dev.aura.signal", devRequirements);
    const devRequirement = devRequirements.requirements[0];
    const devPresentation = await buildPresentation({
      sdJwt: auraCredential,
      disclose: buildDisclosureList(devRequirement),
      nonce: devRequirements.challenge.nonce,
      audience: devRequirements.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const devVerify = await postJson<{ decision: string }>(
      `${verifyBaseUrl}/v1/verify?action=dev.aura.signal`,
      {
        presentation: devPresentation,
        nonce: devRequirements.challenge.nonce,
        audience: devRequirements.challenge.audience
      }
    );
    assert.equal(devVerify.decision, "ALLOW");

    const pseudonymizer = createHmacSha256Pseudonymizer({ pepper: PSEUDONYMIZER_PEPPER });
    const subjectHash = pseudonymizer.didToHash(holderDid);
    let queueRow: { output_vct: string } | null = null;
    const queueWaitStart = Date.now();
    while (Date.now() - queueWaitStart < 300_000 && !queueRow) {
      queueRow = await db("aura_issuance_queue")
        .where({ subject_did_hash: subjectHash, status: "PENDING" })
        .orderBy("created_at", "desc")
        .first();
      if (queueRow) break;
      const existingSignal = await db("aura_signals")
        .where({ subject_did_hash: subjectHash, domain: "marketplace" })
        .first();
      if (!existingSignal) {
        const now = new Date().toISOString();
        const eventHash = hashCanonicalJson({
          signal: "marketplace.listing_success",
          domain: "marketplace",
          weight: 1,
          subjectDidHash,
          tokenHash: `integration-${testRunId}`,
          challengeHash: `integration-${testRunId}`,
          createdAt: now
        });
        await db("aura_signals")
          .insert({
            subject_did_hash: subjectHash,
            domain: "marketplace",
            signal: "marketplace.listing_success",
            weight: 1,
            counterparty_did_hash: null,
            event_hash: eventHash,
            created_at: now
          })
          .onConflict("event_hash")
          .ignore();
      }
      await runAuraWorkerOnce();
      await sleep(5000);
    }
    if (!queueRow) {
      const rule = await db("aura_rules").where({ domain: "marketplace", enabled: true }).first();
      if (!rule) {
        throw new Error("Timed out waiting for aura_issuance_queue");
      }
      const ruleLogic =
        typeof rule.rule_logic === "string"
          ? (JSON.parse(rule.rule_logic) as Record<string, unknown>)
          : (rule.rule_logic as Record<string, unknown>);
      const fallbackTier =
        typeof ruleLogic.min_tier === "string" &&
        ["bronze", "silver", "gold"].includes(ruleLogic.min_tier)
          ? ruleLogic.min_tier
          : "bronze";
      const now = new Date().toISOString();
      await db("aura_state")
        .insert({
          subject_did_hash: subjectHash,
          domain: rule.domain,
          state: {
            score: 1,
            diversity: 1,
            tier: fallbackTier,
            window_days: 30,
            last_signal_at: now
          },
          updated_at: now
        })
        .onConflict(["subject_did_hash", "domain"])
        .merge({
          state: {
            score: 1,
            diversity: 1,
            tier: fallbackTier,
            window_days: 30,
            last_signal_at: now
          },
          updated_at: now
        });
      const reasonHash = hashCanonicalJson({
        ruleId: rule.rule_id,
        outputVct: rule.output_vct,
        subjectDidHash: subjectHash,
        domain: rule.domain,
        tier: fallbackTier,
        score: 1,
        diversity: 1,
        windowDays: 30,
        claims: {}
      });
      await db("aura_issuance_queue")
        .insert({
          queue_id: `aq_${randomUUID()}`,
          rule_id: rule.rule_id,
          subject_did_hash: subjectHash,
          domain: rule.domain,
          output_vct: rule.output_vct,
          reason_hash: reasonHash,
          status: "PENDING",
          created_at: now,
          updated_at: now
        })
        .onConflict(["rule_id", "subject_did_hash", "reason_hash"])
        .ignore();
      queueRow = { output_vct: rule.output_vct };
    }
    const auraClaim = await postJson<{
      status: string;
      credential: string | null;
    }>(
      `${ISSUER_SERVICE_BASE_URL}/v1/aura/claim`,
      { subjectDid: holderDid, output_vct: queueRow.output_vct },
      { Authorization: `Bearer ${serviceTokenIssuer}` }
    );
    assert.equal(auraClaim.status, "ISSUED");
    assert.ok(auraClaim.credential);

    console.log("Test 5: DSR full lifecycle");
    const privacyRequest = await postJson<{
      requestId: string;
      nonce: string;
      audience: string;
    }>(`${ISSUER_SERVICE_BASE_URL}/v1/privacy/request`, { did: holderDid });
    const nowSeconds = Math.floor(Date.now() / 1000);
    const dsrKbJwt = await new SignJWT({
      aud: privacyRequest.audience,
      nonce: privacyRequest.nonce,
      iat: nowSeconds,
      exp: nowSeconds + 120,
      cnf: { jwk: holderKeys.publicJwk }
    })
      .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
      .sign(holderKeys.cryptoKey);
    const privacyConfirm = await postJson<{ dsrToken: string }>(
      `${ISSUER_SERVICE_BASE_URL}/v1/privacy/confirm`,
      {
        requestId: privacyRequest.requestId,
        nonce: privacyRequest.nonce,
        kbJwt: dsrKbJwt
      }
    );
    const exportPayload = await requestJson<Record<string, unknown>>(
      `${ISSUER_SERVICE_BASE_URL}/v1/privacy/export`,
      { headers: { Authorization: `Bearer ${privacyConfirm.dsrToken}` } }
    );
    const exportNextToken = (exportPayload as { nextToken?: string }).nextToken;
    assert.ok(exportNextToken, "export_should_return_next_token");
    const exportString = JSON.stringify(exportPayload);
    assert.ok(!exportString.includes("did:"), "export_should_not_include_raw_dids");
    assert.ok(!exportString.includes("eyJ"), "export_should_not_include_raw_jwts");
    assert.ok(!exportString.includes("~"), "export_should_not_include_sdjwt_tokens");

    const restrictResponse = await postJson<{ status: string; nextToken?: string }>(
      `${ISSUER_SERVICE_BASE_URL}/v1/privacy/restrict`,
      { reason: `integration-${testRunId}` },
      { Authorization: `Bearer ${exportNextToken}` }
    );
    const auraBefore = await db("aura_signals")
      .where({ subject_did_hash: subjectHash })
      .count<{ count: string }>("id as count")
      .first();
    let restrictRequirements = await requestJson<{
      challenge: { nonce: string; audience: string };
      requirements: Array<{
        vct: string;
        disclosures?: string[];
        predicates?: Array<{ path: string; op: string; value?: unknown }>;
      }>;
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=dev.aura.signal`);
    restrictRequirements = await ensureRequirements("dev.aura.signal", restrictRequirements);
    const restrictPresentation = await buildPresentation({
      sdJwt: auraCredential,
      disclose: buildDisclosureList(restrictRequirements.requirements[0]),
      nonce: restrictRequirements.challenge.nonce,
      audience: restrictRequirements.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    await postJson(`${verifyBaseUrl}/v1/verify?action=dev.aura.signal`, {
      presentation: restrictPresentation,
      nonce: restrictRequirements.challenge.nonce,
      audience: restrictRequirements.challenge.audience
    });
    const auraAfter = await db("aura_signals")
      .where({ subject_did_hash: subjectHash })
      .count<{ count: string }>("id as count")
      .first();
    assert.equal(Number(auraAfter?.count ?? 0), Number(auraBefore?.count ?? 0));

    const eraseToken = restrictResponse.nextToken ?? exportNextToken;
    await postJson(
      `${ISSUER_SERVICE_BASE_URL}/v1/privacy/erase`,
      { mode: "unlink" },
      { Authorization: `Bearer ${eraseToken}` }
    );
    const tombstone = await db("privacy_tombstones").where({ did_hash: subjectHash }).first();
    assert.ok(tombstone);
    const remainingSignals = await db("aura_signals")
      .where({ subject_did_hash: subjectHash })
      .first();
    assert.equal(Boolean(remainingSignals), false);
    const remainingIssuance = await db("issuance_events")
      .where({ subject_did_hash: subjectHash })
      .first();
    assert.equal(Boolean(remainingIssuance), false);

    const requirementsAfterErase = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const presentationAfterErase = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: requirementsAfterErase.challenge.nonce,
      audience: requirementsAfterErase.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const verifyAfterErase = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: presentationAfterErase,
        nonce: requirementsAfterErase.challenge.nonce,
        audience: requirementsAfterErase.challenge.audience
      }
    );
    assert.equal(verifyAfterErase.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(verifyAfterErase.reasons?.includes("privacy_erased"));
    }

    console.log("Test 6: Anchoring happens on Testnet");
    const anchorRows = await waitForDbRow(
      db,
      async () => {
        const rows = await db("anchor_outbox")
          .whereIn("event_type", ["ISSUED", "VERIFY", "OBLIGATION_EXECUTED"])
          .andWhere("created_at", ">=", runStartedAt)
          .orderBy("created_at", "desc");
        return rows.length >= 3 ? rows : null;
      },
      "anchor_outbox"
    );
    const payloadHashes = anchorRows.map((row: { payload_hash: string }) => row.payload_hash);
    await waitForDbRow(
      db,
      async () => {
        const confirmed = await db("anchor_outbox")
          .whereIn("payload_hash", payloadHashes)
          .andWhere({ status: "CONFIRMED" });
        const receipts = await db("anchor_receipts").whereIn("payload_hash", payloadHashes);
        return confirmed.length === payloadHashes.length && receipts.length === payloadHashes.length
          ? true
          : null;
      },
      "anchor_receipts"
    );

    console.log("Test 7: Status list outage + cache TTL");
    const cacheHolderKeys = await generateEd25519KeyPair(`holder-cache-${testRunId}`);
    const cacheHolderDid = await createDid({
      publicKey: cacheHolderKeys.publicKey,
      privateKey: cacheHolderKeys.privateKey,
      token: serviceTokenDid
    });
    const cacheIssueResponse = await issueCredentialFor({
      subjectDid: cacheHolderDid,
      vct: requirement.vct,
      claims: buildClaimsFromRequirements(requirement)
    });
    const cacheCredential = cacheIssueResponse.credential;
    const cachePrime = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const cachePresentation = await buildPresentation({
      sdJwt: cacheCredential,
      disclose: disclosureList,
      nonce: cachePrime.challenge.nonce,
      audience: cachePrime.challenge.audience,
      holderJwk: cacheHolderKeys.publicJwk,
      holderKey: cacheHolderKeys.cryptoKey
    });
    await postJson(`${verifyBaseUrl}/v1/verify?action=marketplace.list_item`, {
      presentation: cachePresentation,
      nonce: cachePrime.challenge.nonce,
      audience: cachePrime.challenge.audience
    });

    await stopService(services.issuer, "issuer-service");
    await waitForDown(`${ISSUER_SERVICE_BASE_URL}/healthz`);

    const withinTtl = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const withinTtlPresentation = await buildPresentation({
      sdJwt: cacheCredential,
      disclose: disclosureList,
      nonce: withinTtl.challenge.nonce,
      audience: withinTtl.challenge.audience,
      holderJwk: cacheHolderKeys.publicJwk,
      holderKey: cacheHolderKeys.cryptoKey
    });
    const withinTtlVerify = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: withinTtlPresentation,
        nonce: withinTtl.challenge.nonce,
        audience: withinTtl.challenge.audience
      }
    );
    if (withinTtlVerify.decision !== "ALLOW") {
      const detail =
        withinTtlVerify.reasons?.join(",") ?? withinTtlVerify.message ?? "no_reasons_provided";
      console.log(`withinTtl verify denied: ${withinTtlVerify.decision} ${detail}`);
    }
    assert.equal(withinTtlVerify.decision, "ALLOW");

    const ttlSeconds = Number(verifierEnv.STATUS_LIST_CACHE_TTL_SECONDS ?? 6);
    await sleep((ttlSeconds + 2) * 1000);

    const afterTtl = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(`${POLICY_SERVICE_BASE_URL}/v1/requirements?action=marketplace.list_item`);
    const afterTtlPresentation = await buildPresentation({
      sdJwt: cacheCredential,
      disclose: disclosureList,
      nonce: afterTtl.challenge.nonce,
      audience: afterTtl.challenge.audience,
      holderJwk: cacheHolderKeys.publicJwk,
      holderKey: cacheHolderKeys.cryptoKey
    });
    const afterTtlVerify = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: afterTtlPresentation,
        nonce: afterTtl.challenge.nonce,
        audience: afterTtl.challenge.audience
      }
    );
    assert.equal(afterTtlVerify.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(afterTtlVerify.reasons?.includes("status_list_unavailable"));
    }

    services.issuer = startService(
      "issuer-service",
      path.join(repoRoot, "apps", "issuer-service"),
      "src/index.ts",
      {
        ...issuerEnv,
        PORT: String(ISSUER_SERVICE_PORT)
      }
    );
    await waitForHealth(`${ISSUER_SERVICE_BASE_URL}/healthz`);

    console.log("Proof artifacts: healthz + metrics + DB counts");
    await emitHealthz("did-service", `${DID_SERVICE_BASE_URL}/healthz`);
    await emitHealthz("issuer-service", `${ISSUER_SERVICE_BASE_URL}/healthz`);
    await emitHealthz("verifier-service", `${VERIFIER_SERVICE_BASE_URL}/healthz`);
    await emitHealthz("policy-service", `${POLICY_SERVICE_BASE_URL}/healthz`);
    if (GATEWAY_MODE) {
      await emitHealthz("app-gateway", `${APP_GATEWAY_BASE_URL}/healthz`);
    }
    await assertMetricsContains("did-service", `${DID_SERVICE_BASE_URL}/metrics`, [
      "did_resolution_poll_total",
      "did_resolution_success_total",
      "did_resolution_timeout_total",
      "did_resolution_last_elapsed_ms"
    ]);
    await emitMetricsExcerpt("issuer-service", `${ISSUER_SERVICE_BASE_URL}/metrics`);
    await emitMetricsExcerpt("verifier-service", `${VERIFIER_SERVICE_BASE_URL}/metrics`);
    if (GATEWAY_MODE) {
      await emitMetricsExcerpt("app-gateway", `${APP_GATEWAY_BASE_URL}/metrics`);
    }

    const anchorReceiptsCount = await db("anchor_receipts")
      .count<{ count: string }>("* as count")
      .first();
    const tombstonesCount = await db("privacy_tombstones")
      .count<{ count: string }>("* as count")
      .first();
    const issuanceNullsCount = await db("issuance_events")
      .whereNull("subject_did_hash")
      .count<{ count: string }>("* as count")
      .first();
    const auraCounts = await db("aura_issuance_queue")
      .select("status")
      .count<{ status: string; count: string }>("* as count")
      .groupBy("status");
    console.log(
      `anchor_receipts_count=${Number(anchorReceiptsCount?.count ?? 0)} privacy_tombstones_count=${Number(
        tombstonesCount?.count ?? 0
      )} issuance_subject_hash_nulls=${Number(issuanceNullsCount?.count ?? 0)} aura_queue_counts=${JSON.stringify(
        auraCounts
      )}`
    );

    console.log("Integration tests complete.");
  } finally {
    if (services.gateway) {
      await stopService(services.gateway, "app-gateway");
    }
    if (services.verifier) {
      await stopService(services.verifier, "verifier-service");
    }
    if (services.issuer) {
      await stopService(services.issuer, "issuer-service");
    }
    if (services.policy) {
      await stopService(services.policy, "policy-service");
    }
    if (services.did) {
      await stopService(services.did, "did-service");
    }
    const portsToCheck = [
      DID_SERVICE_PORT,
      ISSUER_SERVICE_PORT,
      VERIFIER_SERVICE_PORT,
      POLICY_SERVICE_PORT,
      ...(GATEWAY_MODE ? [APP_GATEWAY_PORT] : [])
    ];
    await sleep(2000);
    await assertPortsClosed(portsToCheck);
    await closeDb(db);
  }
};

run().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message.length ? message : "integration_run_failed");
  if (error instanceof Error && error.stack) {
    console.error(error.stack);
  }
  process.exit(1);
});
