import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID, randomBytes } from "node:crypto";
import net from "node:net";
import { strict as assert } from "node:assert";
import { readFile, writeFile } from "node:fs/promises";
import { createDb, runMigrations, closeDb, type DbClient } from "@cuncta/db";
import { presentSdJwtVc } from "@cuncta/sdjwt";
import {
  classifyHederaFailure,
  createHmacSha256Pseudonymizer,
  hashCanonicalJson
} from "@cuncta/shared";
import { Agent, setGlobalDispatcher } from "undici";
import { SignJWT, importJWK, decodeJwt } from "jose";
import { base58btc } from "multiformats/bases/base58";
import { getPublicKey, sign, hashes } from "@noble/ed25519";
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

const walletCliEntry = path.join(repoRoot, "apps", "wallet-cli", "src", "cli.ts");
const parseLastJsonFromStdout = (stdout: string) => {
  const lines = stdout.trim().split(/\r?\n/);
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const line = lines[i]?.trim() ?? "";
    if (!line.startsWith("{") || !line.endsWith("}")) continue;
    try {
      return JSON.parse(line) as unknown;
    } catch {
      // ignore
    }
  }
  return null;
};

const tailLines = (value: string, maxLines = 200) => {
  const lines = value.split(/\r?\n/);
  if (lines.length <= maxLines) return value;
  return lines.slice(lines.length - maxLines).join("\n");
};

const writeJsonArgFile = async (baseDir: string, label: string, payload: unknown) => {
  const filePath = path.join(baseDir, `${label}-${randomUUID()}.json`);
  await writeFile(filePath, JSON.stringify(payload), "utf8");
  return filePath;
};

const redactSecrets = (value: string) => {
  let next = value;
  // Redact any configured payer private key values if they appear in child output.
  const secrets = [
    process.env.TESTNET_PAYER_PRIVATE_KEY,
    process.env.HEDERA_PAYER_PRIVATE_KEY,
    process.env.HEDERA_OPERATOR_PRIVATE_KEY
  ]
    .filter((v): v is string => typeof v === "string" && v.trim().length > 0)
    .map((v) => v.trim());
  for (const secret of secrets) {
    // Replace all occurrences; keep it simple and robust.
    next = next.split(secret).join("[REDACTED]");
  }
  return next;
};

type StepHttpDiagnostic = {
  step: string;
  method: string;
  url: string;
  status?: number;
  body?: string;
  error?: string;
  at: string;
};
const stepHttpDiagnostics = new Map<string, StepHttpDiagnostic>();

const recordStepHttpDiagnostic = (
  step: string,
  input: {
    method: string;
    url: string;
    status?: number;
    body?: string;
    error?: string;
  }
) => {
  stepHttpDiagnostics.set(step, {
    step,
    method: input.method,
    url: input.url,
    status: input.status,
    body: input.body ? input.body.slice(0, 2000) : undefined,
    error: input.error,
    at: new Date().toISOString()
  });
};

const probeHealthz = async (baseUrl: string, timeoutMs = 2500) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("health_probe_timeout"), timeoutMs);
  timeout.unref?.();
  try {
    const response = await fetch(`${baseUrl}/healthz`, { signal: controller.signal });
    const body = await response.text().catch(() => "");
    return {
      ok: response.ok,
      status: response.status,
      body: body.slice(0, 500)
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    clearTimeout(timeout);
  }
};

const runWalletCli = async (args: string[], envOverrides: Record<string, string>) => {
  const env = { ...process.env, ...envOverrides };
  const timeoutMsRaw = env.WALLET_CLI_TIMEOUT_MS;
  const command = args[0] ?? "unknown";
  const defaultTimeoutMsForCommand =
    command === "did:create:auto" ? 180_000 : WALLET_CLI_TIMEOUT_MS;
  const timeoutMs =
    Number.isFinite(Number(timeoutMsRaw)) && Number(timeoutMsRaw) > 0
      ? Number(timeoutMsRaw)
      : defaultTimeoutMsForCommand;
  const stepLabel = `${currentIntegrationStep}|wallet-cli:${command}`;
  const commandHasTerminalSuccessMarker = (cmd: string) =>
    cmd === "did:create:auto" ||
    cmd === "did:rotate" ||
    cmd === "vc:acquire" ||
    cmd === "vp:respond";
  // Keep strict no-output detection, but allow slightly larger silence budgets for
  // commands that can legitimately spend longer in crypto/network paths before first log.
  const noOutputTimeoutMs =
    command === "did:create:auto"
      ? 45_000
      : command === "vp:respond"
        ? 45_000
        : command === "vc:acquire"
          ? 45_000
          : 30_000;
  const started = Date.now();
  console.log(
    `[wallet-cli] start step=${stepLabel} timeoutMs=${timeoutMs} noOutputTimeoutMs=${noOutputTimeoutMs} args=${args.join(
      " "
    )}`
  );
  return await new Promise<{ exitCode: number; stdout: string; stderr: string }>(
    (resolve, reject) => {
      const child = spawn("tsx", [walletCliEntry, ...args], {
        env,
        stdio: ["ignore", "pipe", "pipe"],
        shell: true
      });
      let stdout = "";
      let stderr = "";
      let timedOut = false;
      let noOutputFor30s = false;
      let successMarkerSeen = false;
      let settled = false;
      let lastOutputAt = Date.now();
      const buildDiagError = async (reason: "wallet_cli_timeout" | "wallet_cli_no_output_30s") => {
        const stdoutRedacted = redactSecrets(stdout);
        const stderrRedacted = redactSecrets(stderr);
        const httpDiag = stepHttpDiagnostics.get(currentIntegrationStep) ?? null;
        const [gatewayHealth, issuerHealth, verifierHealth] = await Promise.all([
          probeHealthz(APP_GATEWAY_BASE_URL),
          probeHealthz(ISSUER_SERVICE_BASE_URL),
          probeHealthz(VERIFIER_SERVICE_BASE_URL)
        ]);
        return new Error(
          `${reason} step=${stepLabel} timeoutMs=${timeoutMs} args=${args.join(" ")} ` +
            `lastOutputAgoMs=${Date.now() - lastOutputAt} ` +
            `stdoutTailLines=${JSON.stringify(tailLines(stdoutRedacted, 200))} ` +
            `stderrTailLines=${JSON.stringify(tailLines(stderrRedacted, 200))} ` +
            `health=${JSON.stringify({ gatewayHealth, issuerHealth, verifierHealth })} ` +
            `lastHttp=${JSON.stringify(httpDiag)}`
        );
      };
      const timeout = setTimeout(() => {
        if (settled) return;
        // Some commands can emit a terminal success payload but keep handles open.
        // If we already saw terminal success, stop the child without treating it as failure.
        if (commandHasTerminalSuccessMarker(command) && successMarkerSeen) {
          try {
            child.kill("SIGKILL");
          } catch {
            // ignore
          }
          return;
        }
        timedOut = true;
        try {
          child.kill("SIGKILL");
        } catch {
          // ignore
        }
      }, timeoutMs);
      timeout.unref?.();
      const settleSuccess = () => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        clearInterval(stuckDetector);
        resolve({ exitCode: 0, stdout: redactSecrets(stdout), stderr: redactSecrets(stderr) });
        // Best-effort cleanup: some wallet-cli invocations can keep handles open in subprocess deps.
        try {
          child.kill("SIGTERM");
        } catch {
          // ignore
        }
      };
      child.once("spawn", () => {
        // Start the no-output budget when the child process actually starts.
        lastOutputAt = Date.now();
      });
      child.stdout?.on("data", (chunk) => {
        lastOutputAt = Date.now();
        const text = String(chunk);
        stdout += text;
        // Some wallet-cli commands can emit a terminal success payload and then keep handles open.
        // Treat this as terminal success for lifecycle/timeout detection.
        if (command === "did:create:auto" && /\bdid=did:[^\s]+/.test(text)) {
          successMarkerSeen = true;
        }
        if (
          command === "did:rotate" &&
          stdout.includes('"ok": true') &&
          stdout.includes('"rotated": true')
        ) {
          successMarkerSeen = true;
        }
        if (
          command === "vc:acquire" &&
          stdout.includes('"ok": true') &&
          (stdout.includes('"configId":') || stdout.includes('"config_id":'))
        ) {
          successMarkerSeen = true;
        }
        if (
          command === "vp:respond" &&
          stdout.includes('"event":"vp.respond.result"') &&
          stdout.includes('"decision":"ALLOW"')
        ) {
          successMarkerSeen = true;
        }
        if (commandHasTerminalSuccessMarker(command) && successMarkerSeen) {
          settleSuccess();
        }
      });
      child.stderr?.on("data", (chunk) => {
        lastOutputAt = Date.now();
        stderr += String(chunk);
      });
      const stuckDetector = setInterval(() => {
        if (settled) return;
        if (Date.now() - lastOutputAt >= noOutputTimeoutMs) {
          const shouldTreatAsNoOutput = !(
            commandHasTerminalSuccessMarker(command) && successMarkerSeen
          );
          noOutputFor30s = shouldTreatAsNoOutput;
          if (shouldTreatAsNoOutput) {
            try {
              child.kill("SIGKILL");
            } catch {
              // ignore
            }
          }
        }
      }, 5000);
      stuckDetector.unref?.();
      child.on("close", async (code) => {
        if (settled) {
          return;
        }
        clearTimeout(timeout);
        clearInterval(stuckDetector);
        const exitCode = typeof code === "number" ? code : 1;
        const elapsedMs = Date.now() - started;
        console.log(
          `[wallet-cli] end step=${stepLabel} exitCode=${exitCode} elapsedMs=${elapsedMs}`
        );
        if (timedOut && !(commandHasTerminalSuccessMarker(command) && successMarkerSeen)) {
          reject(await buildDiagError("wallet_cli_timeout"));
          return;
        }
        if (noOutputFor30s && !(commandHasTerminalSuccessMarker(command) && successMarkerSeen)) {
          reject(await buildDiagError("wallet_cli_no_output_30s"));
          return;
        }
        if (commandHasTerminalSuccessMarker(command) && successMarkerSeen) {
          resolve({ exitCode: 0, stdout: redactSecrets(stdout), stderr: redactSecrets(stderr) });
          return;
        }
        resolve({ exitCode, stdout: redactSecrets(stdout), stderr: redactSecrets(stderr) });
      });
    }
  );
};

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
const SOCIAL_MODE = process.env.SOCIAL_MODE === "1";
const NODE_ENV = process.env.NODE_ENV ?? "development";
const DEBUG_VERIFY_REASONS = (process.env.GATEWAY_VERIFY_DEBUG_REASONS ?? "true") === "true";
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

// DID rotation can take longer to propagate through mirror nodes than initial creation.
// Keep it configurable so testnet runs can be reliable without making local iteration painful.
const DID_ROTATION_VISIBILITY_TIMEOUT_MS = clampInt(
  process.env.DID_ROTATION_VISIBILITY_TIMEOUT_MS,
  60_000,
  1_800_000,
  600_000
);
const DID_ROTATION_VISIBILITY_INTERVAL_MS = clampInt(
  process.env.DID_ROTATION_VISIBILITY_INTERVAL_MS,
  1000,
  30_000,
  4000
);
const DID_ROTATION_VISIBILITY_ATTEMPTS = Math.max(
  1,
  Math.floor(DID_ROTATION_VISIBILITY_TIMEOUT_MS / DID_ROTATION_VISIBILITY_INTERVAL_MS)
);
const HARNESS_HTTP_TIMEOUT_MS = clampInt(
  process.env.HARNESS_HTTP_TIMEOUT_MS,
  5000,
  120_000,
  90_000
);
// Phase 0 debug mode: default wallet-cli timeout to 60s.
const WALLET_CLI_TIMEOUT_MS = clampInt(
  process.env.WALLET_CLI_TIMEOUT_MS,
  60_000,
  3_600_000,
  60_000
);
const FETCH_TIMEOUT_MS = Math.min(1_500_000, DID_VISIBILITY_TOTAL_TIMEOUT_MS + 60_000);
const ANCHOR_PHASE_TIMEOUT_MS = clampInt(
  process.env.ANCHOR_PHASE_TIMEOUT_MS,
  30_000,
  600_000,
  180_000
);
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
  const payerIdAny = process.env.TESTNET_PAYER_ACCOUNT_ID ?? process.env.HEDERA_PAYER_ACCOUNT_ID;
  const payerKeyAny = process.env.TESTNET_PAYER_PRIVATE_KEY ?? process.env.HEDERA_PAYER_PRIVATE_KEY;
  if (!payerIdAny || !payerKeyAny) {
    throw new Error("operator_as_payer_disabled_in_production");
  }
}

// CI/self-funded Phase 0: prefer TESTNET_PAYER_* in harness mode.
if (USER_PAYS_MODE) {
  // Treat payer credentials as required inputs (never inferred from operator keys).
  REQUIRED_ENV.push("TESTNET_PAYER_ACCOUNT_ID", "TESTNET_PAYER_PRIVATE_KEY");
  const payerId = process.env.TESTNET_PAYER_ACCOUNT_ID ?? process.env.HEDERA_PAYER_ACCOUNT_ID;
  const payerKey = process.env.TESTNET_PAYER_PRIVATE_KEY ?? process.env.HEDERA_PAYER_PRIVATE_KEY;
  if (!payerId || !payerKey) {
    throw new Error(
      "TESTNET_PAYER_ACCOUNT_ID and TESTNET_PAYER_PRIVATE_KEY required for user-pays test flows"
    );
  }
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
console.log(`Harness gateway HTTP timeout: timeoutMs=${HARNESS_HTTP_TIMEOUT_MS}`);
if (process.env.RUN_TESTNET_INTEGRATION === "1" && !DID_WAIT_FOR_VISIBILITY) {
  console.warn(
    "WARNING: DID_WAIT_FOR_VISIBILITY=false may reduce correctness; use only for local iteration."
  );
}

const DATABASE_URL = process.env.DATABASE_URL!;
const SERVICE_JWT_SECRET = process.env.SERVICE_JWT_SECRET!;
const SERVICE_JWT_SECRET_DID = process.env.SERVICE_JWT_SECRET_DID ?? `${SERVICE_JWT_SECRET}-did`;
const SERVICE_JWT_SECRET_ISSUER =
  process.env.SERVICE_JWT_SECRET_ISSUER ?? `${SERVICE_JWT_SECRET}-issuer`;
const SERVICE_JWT_SECRET_VERIFIER =
  process.env.SERVICE_JWT_SECRET_VERIFIER ?? `${SERVICE_JWT_SECRET}-verifier`;
const SERVICE_JWT_SECRET_SOCIAL =
  process.env.SERVICE_JWT_SECRET_SOCIAL ?? `${SERVICE_JWT_SECRET}-social`;
const SERVICE_JWT_AUDIENCE = process.env.SERVICE_JWT_AUDIENCE ?? "cuncta-internal";
const SERVICE_JWT_AUDIENCE_DID = process.env.SERVICE_JWT_AUDIENCE_DID ?? "cuncta.service.did";
const SERVICE_JWT_AUDIENCE_ISSUER =
  process.env.SERVICE_JWT_AUDIENCE_ISSUER ?? "cuncta.service.issuer";
const SERVICE_JWT_AUDIENCE_VERIFIER =
  process.env.SERVICE_JWT_AUDIENCE_VERIFIER ?? "cuncta.service.verifier";
const SERVICE_JWT_AUDIENCE_SOCIAL =
  process.env.SERVICE_JWT_AUDIENCE_SOCIAL ?? "cuncta.service.social";
const PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER!;

const DEFAULT_PORTS = {
  did: 3001,
  issuer: 3002,
  verifier: 3003,
  policy: 3004,
  social: 3005,
  gateway: 3010
};

let DID_SERVICE_BASE_URL = "";
let ISSUER_SERVICE_BASE_URL = "";
let VERIFIER_SERVICE_BASE_URL = "";
let POLICY_SERVICE_BASE_URL = "";
let SOCIAL_SERVICE_BASE_URL = "";
let ISSUER_BASE_URL = "";
let APP_GATEWAY_BASE_URL = "";
let DID_SERVICE_PORT = DEFAULT_PORTS.did;
let ISSUER_SERVICE_PORT = DEFAULT_PORTS.issuer;
let VERIFIER_SERVICE_PORT = DEFAULT_PORTS.verifier;
let POLICY_SERVICE_PORT = DEFAULT_PORTS.policy;
let SOCIAL_SERVICE_PORT = DEFAULT_PORTS.social;
let APP_GATEWAY_PORT = DEFAULT_PORTS.gateway;

const nodeCmd = process.execPath;
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
const GATEWAY_DEVICE_ID = randomUUID();
const SERVICE_LOG_TAIL_MAX_LINES = 300;
const serviceLogTail = new Map<string, string[]>();
let currentIntegrationStep = "bootstrap";

const appendServiceLogTail = (name: string, chunk: unknown, stream: "stdout" | "stderr") => {
  const text = Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk ?? "");
  const lines = text.split(/\r?\n/).filter((line) => line.length > 0);
  if (!lines.length) return;
  const current = serviceLogTail.get(name) ?? [];
  for (const line of lines) {
    current.push(`[${stream}] ${line}`);
  }
  if (current.length > SERVICE_LOG_TAIL_MAX_LINES) {
    current.splice(0, current.length - SERVICE_LOG_TAIL_MAX_LINES);
  }
  serviceLogTail.set(name, current);
};

const toBase64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const fromBase64Url = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));
const sha256Base64Url = (value: string) => createHash("sha256").update(value).digest("base64url");
const sha256Hex = (value: string) => createHash("sha256").update(value).digest("hex");

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

  const social = await resolveServiceUrl(
    "SOCIAL_SERVICE_BASE_URL",
    "SOCIAL_SERVICE_PORT",
    DEFAULT_PORTS.social
  );
  SOCIAL_SERVICE_BASE_URL = social.url;
  SOCIAL_SERVICE_PORT = social.port;

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

const resolvePayerCredentials = () => {
  // Phase 0 invariant: integration test harnesses must not contain any operator-as-payer fallback.
  // CI (and local runs) must provide explicit payer credentials.
  const payerAccountId = (
    process.env.TESTNET_PAYER_ACCOUNT_ID ?? process.env.HEDERA_PAYER_ACCOUNT_ID
  )?.trim();
  const payerPrivateKey = (
    process.env.TESTNET_PAYER_PRIVATE_KEY ?? process.env.HEDERA_PAYER_PRIVATE_KEY
  )?.trim();
  if (!payerAccountId || !payerPrivateKey) {
    throw new Error(
      "payer_credentials_required: set TESTNET_PAYER_ACCOUNT_ID + TESTNET_PAYER_PRIVATE_KEY (or HEDERA_PAYER_*). No operator fallback in test harnesses."
    );
  }
  return { payerAccountId, payerPrivateKey };
};

const ensurePolicySigningJwk = async () => {
  // Integration harness must be runnable even if a developer has a stale/bad key in .env.
  // Policy signing is dev/test only for the harness (POLICY_SIGNING_BOOTSTRAP=true).
  const existing = process.env.POLICY_SIGNING_JWK;
  if (existing && existing.trim().length > 0) {
    try {
      const parsed = JSON.parse(existing) as Record<string, unknown>;
      // Validate shape by attempting an import. This catches bad Ed25519 key lengths early.
      await importJWK(parsed as never, "EdDSA");
      return existing;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      console.warn(
        `[diag] POLICY_SIGNING_JWK invalid in env; generating ephemeral key for harness (${msg})`
      );
    }
  }
  const policyKeys = await generateEd25519KeyPair(`policy-${randomUUID()}`);
  return JSON.stringify(policyKeys.jwk);
};

const ensureAnchorAuthSecret = () => {
  return process.env.ANCHOR_AUTH_SECRET ?? `${randomUUID()}${randomUUID()}`;
};
const ensureUserPaysHandoffSecret = () => {
  return process.env.USER_PAYS_HANDOFF_SECRET ?? `${randomUUID()}${randomUUID()}`;
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
    // Credential issuance goes to issuer directly in self-funded mode (OID4VCI).
  }
  if (USER_PAYS_MODE) {
    if (url.startsWith(`${DID_SERVICE_BASE_URL}/v1/dids/create/`)) {
      throw new Error(`user_pays_mode_direct_did_call_blocked: ${url}`);
    }
  }
};

const toRouteName = (url: string) => {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return url;
  }
};

const isGatewayRequestUrl = (url: string) => {
  if (!APP_GATEWAY_BASE_URL) return false;
  try {
    return new URL(url).origin === new URL(APP_GATEWAY_BASE_URL).origin;
  } catch {
    return url.startsWith(APP_GATEWAY_BASE_URL);
  }
};

const fetchWithHarnessTimeout = async (
  url: string,
  init: RequestInit | undefined,
  options?: { stepName?: string; routeName?: string; timeoutMs?: number }
) => {
  const timeoutMs = options?.timeoutMs ?? HARNESS_HTTP_TIMEOUT_MS;
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => {
    timeoutController.abort("harness_http_timeout");
  }, timeoutMs);
  timeout.unref?.();
  const upstreamSignal = init?.signal;
  const onAbort = () => timeoutController.abort("harness_http_aborted");
  upstreamSignal?.addEventListener("abort", onAbort, { once: true });
  const requestInit: RequestInit = {
    ...(init ?? {}),
    signal: timeoutController.signal
  };
  let timedOut = false;
  timeoutController.signal.addEventListener(
    "abort",
    () => {
      if (timeoutController.signal.reason === "harness_http_timeout") {
        timedOut = true;
      }
    },
    { once: true }
  );
  try {
    return await fetch(url, requestInit);
  } catch (error) {
    if (timedOut) {
      const routeName = options?.routeName ?? toRouteName(url);
      const stepName = options?.stepName ?? currentIntegrationStep;
      const method = (requestInit.method ?? init?.method ?? "GET").toUpperCase();
      process.exitCode = 1;
      throw new Error(
        `HARNESS_HTTP_TIMEOUT step=${stepName} method=${method} route=${routeName} timeoutMs=${timeoutMs}`
      );
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    upstreamSignal?.removeEventListener("abort", onAbort);
  }
};

const requestJson = async <T>(
  url: string,
  init?: RequestInit,
  options?: { stepName?: string; routeName?: string; timeoutMs?: number }
): Promise<T> => {
  const stepName = options?.stepName ?? currentIntegrationStep;
  const method = (init?.method ?? "GET").toUpperCase();
  const response = isGatewayRequestUrl(url)
    ? await fetchWithHarnessTimeout(url, init, options)
    : await fetch(url, init);
  if (!response.ok) {
    const body = await response.text();
    recordStepHttpDiagnostic(stepName, {
      method,
      url,
      status: response.status,
      body
    });
    const error = new Error(`HTTP ${response.status} for ${url}: ${body}`) as Error & {
      status?: number;
      url?: string;
      body?: string;
      method?: string;
      stepName?: string;
    };
    error.status = response.status;
    error.url = url;
    error.body = body;
    error.method = method;
    error.stepName = stepName;
    throw error;
  }
  recordStepHttpDiagnostic(stepName, {
    method,
    url,
    status: response.status,
    body: "<ok>"
  });
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

const getAuraClaimRetryReason = (
  error: unknown
): "not_ready" | "processing" | "rate_limited" | null => {
  const err = error as {
    status?: number;
    body?: string;
    message?: string;
  };
  const status = typeof err?.status === "number" ? err.status : null;
  const body = typeof err?.body === "string" ? err.body : "";
  const parseBodyError = () => {
    if (!body.trim().startsWith("{")) return null;
    try {
      return JSON.parse(body) as { error?: string; details?: string };
    } catch {
      return null;
    }
  };
  const parsed = parseBodyError();
  if (status === 404 && parsed?.error === "aura_not_ready") {
    return "not_ready";
  }
  if (
    status === 409 &&
    parsed?.error === "invalid_request" &&
    String(parsed?.details ?? "").includes("PROCESSING")
  ) {
    return "processing";
  }
  if (status === 429 && parsed?.error === "rate_limited") {
    return "rate_limited";
  }
  const message = typeof err?.message === "string" ? err.message : "";
  if (message.includes("aura_not_ready")) return "not_ready";
  if (message.includes("Aura claim unavailable") && message.includes("status=PROCESSING"))
    return "processing";
  if (message.includes("HTTP 429") && message.includes("rate_limited")) return "rate_limited";
  return null;
};

const getAuraOfferRetryReason = (error: unknown): "not_ready" | "rate_limited" | null => {
  const err = error as {
    status?: number;
    body?: string;
    message?: string;
  };
  const status = typeof err?.status === "number" ? err.status : null;
  const body = typeof err?.body === "string" ? err.body : "";
  const parseBodyError = () => {
    if (!body.trim().startsWith("{")) return null;
    try {
      return JSON.parse(body) as { error?: string; details?: string };
    } catch {
      return null;
    }
  };
  const parsed = parseBodyError();
  if (status === 404 && parsed?.error === "aura_not_ready") {
    return "not_ready";
  }
  if (status === 429 && parsed?.error === "rate_limited") {
    return "rate_limited";
  }
  const message = typeof err?.message === "string" ? err.message : "";
  if (message.includes("aura_not_ready")) return "not_ready";
  if (message.includes("HTTP 429") && message.includes("rate_limited")) return "rate_limited";
  return null;
};

const getRequirementsRetryReason = (error: unknown): "temporarily_unavailable" | null => {
  const err = error as {
    status?: number;
    body?: string;
    message?: string;
  };
  const status = typeof err?.status === "number" ? err.status : null;
  const body = typeof err?.body === "string" ? err.body : "";
  const parseBodyError = () => {
    if (!body.trim().startsWith("{")) return null;
    try {
      return JSON.parse(body) as { error?: string; details?: string };
    } catch {
      return null;
    }
  };
  const parsed = parseBodyError();
  if (status === 503 && parsed?.error === "requirements_unavailable") {
    return "temporarily_unavailable";
  }
  const message = typeof err?.message === "string" ? err.message : "";
  if (message.includes("HTTP 503") && message.includes("requirements_unavailable")) {
    return "temporarily_unavailable";
  }
  return null;
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
  let lastStatus: number | null = null;
  let lastBody = "";
  while (Date.now() - started < timeoutMs) {
    for (const target of targets) {
      try {
        const response = await fetch(target);
        lastStatus = response.status;
        if (response.ok) {
          const data = (await response.json()) as { ok?: boolean };
          if (data.ok !== false) {
            return;
          }
        } else {
          lastBody = await response.text().catch(() => "");
        }
      } catch {
        // ignore
      }
    }
    await sleep(1000);
  }
  throw new Error(
    `Health check timed out for ${url} lastStatus=${lastStatus ?? "null"} lastBody=${lastBody.slice(0, 500)}`
  );
};

const waitForPortListening = async (port: number, timeoutMs = 120_000, host = "127.0.0.1") => {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await isPortListening(port, host, 500)) return;
    await sleep(500);
  }
  throw new Error(`port_listen_timeout host=${host} port=${port}`);
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

const isHealthyOnce = async (url: string, timeoutMs = 1500) => {
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
  for (const target of targets) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("health_check_timeout"), timeoutMs);
    timeout.unref?.();
    try {
      const res = await fetch(target, { signal: controller.signal });
      if (!res.ok) continue;
      const data = (await res.json().catch(() => ({}))) as { ok?: boolean };
      if (data.ok !== false) return true;
    } catch {
      // ignore
    } finally {
      clearTimeout(timeout);
    }
  }
  return false;
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
  let attempt = 0;
  try {
    return await waitFor(
      "did_resolved",
      async () => {
        attempt += 1;
        try {
          const resolved = await requestJson<{ didDocument?: Record<string, unknown> }>(
            `${DID_SERVICE_BASE_URL}/v1/dids/resolve/${encoded}`
          );
          const hasDoc = Boolean(
            resolved?.didDocument && Object.keys(resolved.didDocument).length > 0
          );
          if (hasDoc) {
            return {
              done: true,
              value: { attempts: attempt, elapsedMs: Date.now() - started },
              lastResponse: { attempt, hasDoc }
            };
          }
          // "Not yet visible" is expected during mirror lag / propagation.
          return { done: false, lastResponse: { attempt, hasDoc } };
        } catch (error) {
          // Mirror lag / propagation should not fail the wait loop; capture context.
          const msg = error instanceof Error ? error.message : String(error);
          return { done: false, lastResponse: { attempt, error: msg } };
        }
      },
      { timeoutMs: totalTimeoutMs, intervalMs }
    );
  } catch (error) {
    // On timeout, probe health to distinguish "down" vs "slow propagation".
    const detail = error instanceof Error ? error.message : String(error);
    const didHealth = await isHealthyOnce(`${DID_SERVICE_BASE_URL}/healthz`);
    console.error(
      `[diag] did_resolution_timeout did=${did} attempts=${attempt} didServiceHealth=${didHealth} error=${detail}`
    );
    throw error;
  }
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
  let capturedStdout = "";
  let capturedStderr = "";
  proc.stdout?.on("data", (data) => {
    appendServiceLogTail(name, data, "stdout");
    capturedStdout += String(data);
    if (capturedStdout.length > 64_000) {
      capturedStdout = capturedStdout.slice(-64_000);
    }
    process.stdout.write(`[${name}] ${data}`);
  });
  proc.stderr?.on("data", (data) => {
    appendServiceLogTail(name, data, "stderr");
    capturedStderr += String(data);
    if (capturedStderr.length > 64_000) {
      capturedStderr = capturedStderr.slice(-64_000);
    }
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
  (
    proc as ChildProcess & { __capturedOutput?: () => { stdout: string; stderr: string } }
  ).__capturedOutput = () => ({
    stdout: capturedStdout,
    stderr: capturedStderr
  });
  return proc;
};

const ensureServiceRunning = async (input: {
  name: string;
  baseUrl: string;
  start: () => ChildProcess;
  healthPath?: string;
}) => {
  const healthUrl = `${input.baseUrl}${input.healthPath ?? "/healthz"}`;
  if (await isHealthyOnce(healthUrl)) {
    console.log(`[${input.name}] using existing at ${input.baseUrl}`);
    return null;
  }
  const startupTimeoutMsRaw = Number(process.env.SERVICE_START_TIMEOUT_MS ?? "90000");
  const startupTimeoutMs =
    Number.isFinite(startupTimeoutMsRaw) && startupTimeoutMsRaw > 0 ? startupTimeoutMsRaw : 90000;
  const startupAttemptsRaw = Number(process.env.SERVICE_START_ATTEMPTS ?? "3");
  const startupAttempts =
    Number.isFinite(startupAttemptsRaw) && startupAttemptsRaw > 0
      ? Math.floor(startupAttemptsRaw)
      : 3;
  const servicePort = parsePort(input.baseUrl, 80);
  let lastError: unknown;
  for (let attempt = 1; attempt <= startupAttempts; attempt += 1) {
    const proc = input.start();
    // Give startup logs a brief window to surface immediate bind failures (e.g., EADDRINUSE)
    // before we enter health polling.
    await sleep(300);
    try {
      await waitForHealth(healthUrl, startupTimeoutMs);
      return proc;
    } catch (error) {
      const captured = (
        proc as ChildProcess & { __capturedOutput?: () => { stdout: string; stderr: string } }
      ).__capturedOutput?.();
      const startupOutput = `${captured?.stdout ?? ""}\n${captured?.stderr ?? ""}`;
      if (startupOutput.includes("EADDRINUSE")) {
        const healthy = await isHealthyOnce(healthUrl, 3000);
        if (healthy) {
          console.warn(`[${input.name}] startup EADDRINUSE; adopting healthy existing service`);
          await stopService(proc, input.name);
          return null;
        }
      }
      lastError = error;
      const detail = error instanceof Error ? error.message : String(error);
      console.warn(
        `[${input.name}] startup attempt=${attempt} failed healthUrl=${healthUrl} timeoutMs=${startupTimeoutMs} error=${detail}`
      );
      const startupOutputTrimmed = startupOutput.trim();
      if (startupOutputTrimmed.length > 0) {
        console.warn(
          `[diag] ${input.name} captured startup output (last 4000 chars)\n${startupOutputTrimmed.slice(-4000)}`
        );
      } else {
        const listening = await isPortListening(servicePort).catch(() => false);
        console.warn(
          `[diag] ${input.name} no startup output captured pid=${proc.pid ?? "unknown"} exitCode=${proc.exitCode ?? "running"} signalCode=${proc.signalCode ?? "none"} portListening=${listening}`
        );
      }
      emitServiceLogTail(input.name, 80);
      await stopService(proc, input.name);
      if (attempt < startupAttempts) {
        await sleep(1000);
        continue;
      }
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error(String(lastError ?? `${input.name}_startup_failed`));
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

const sleepMs = async (ms: number) => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

const withTimeout = async <T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string
): Promise<T> => {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`timeout:${label}`)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
};

const jitteredBackoffMs = (attempt: number, baseDelayMs: number, maxDelayMs: number) => {
  const raw = Math.min(maxDelayMs, baseDelayMs * 2 ** Math.max(0, attempt - 1));
  const jitter = raw * 0.2 * (Math.random() * 2 - 1);
  return Math.max(0, Math.round(raw + jitter));
};

const runWithHederaRetries = async <T>(input: {
  label: string;
  maxAttempts?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  timeoutMs?: number;
  messageHashPrefix?: string;
  fn: (attempt: number) => Promise<T>;
}): Promise<T> => {
  const maxAttempts = input.maxAttempts ?? 3;
  const baseDelayMs = input.baseDelayMs ?? 500;
  const maxDelayMs = input.maxDelayMs ?? 4000;
  const timeoutMs = input.timeoutMs ?? 15_000;

  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await withTimeout(input.fn(attempt), timeoutMs, input.label);
    } catch (error) {
      lastError = error;
      const classification = classifyHederaFailure(error);
      const diag = {
        label: input.label,
        attempt,
        maxAttempts,
        kind: classification.kind,
        code: classification.code,
        status: classification.status,
        txId: classification.txId,
        messageHashPrefix: input.messageHashPrefix
      };
      console.warn(`[hedera.retry] ${JSON.stringify(diag)}`);

      if (classification.kind === "deterministic") {
        throw new Error(`DETERMINISTIC_FAILURE: hedera_operation_failed ${JSON.stringify(diag)}`);
      }
      if (attempt === maxAttempts) break;
      await sleepMs(jitteredBackoffMs(attempt, baseDelayMs, maxDelayMs));
    }
  }

  const classification = classifyHederaFailure(lastError);
  const finalDiag = {
    label: input.label,
    attempts: maxAttempts,
    kind: classification.kind,
    code: classification.code,
    status: classification.status,
    txId: classification.txId,
    messageHashPrefix: input.messageHashPrefix
  };
  throw new Error(
    `INFRA_FAILURE: hedera_did_create_failed_after_retries ${JSON.stringify(finalDiag)}`
  );
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
    return await runWithHederaRetries({
      label: "did_create_user_pays",
      fn: async () => {
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
      }
    });
  };

  // Self-funded only: always use user-pays (registrar) for DID creation.
  const did = await createViaUserPays();
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
  const issueUrl = `${ISSUER_SERVICE_BASE_URL}/v1/admin/issue`;
  const token = await createServiceToken(
    SERVICE_JWT_AUDIENCE_ISSUER,
    SERVICE_JWT_SECRET_ISSUER,
    "issuer:internal_issue"
  );
  const headers = { Authorization: `Bearer ${token}` };
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
    "social_action_log",
    "social_actions_log",
    "social_banter_permissions",
    "social_banter_reactions",
    "social_banter_messages",
    "social_space_banter_threads",
    "social_presence_status_messages",
    "social_space_member_restrictions",
    "social_space_moderation_actions",
    "sync_session_permissions",
    "sync_session_events",
    "sync_session_participants",
    "sync_session_reports",
    "sync_sessions",
    "social_space_posts",
    "social_space_memberships",
    "social_spaces",
    "social_replies",
    "social_post_content",
    "social_reports",
    "social_follows",
    "social_posts",
    "social_profiles",
    "audit_logs",
    "issuer_keys"
  ];
  await db.raw(buildTruncateSql(tables));
  await db("policies").update({ policy_hash: null, policy_signature: null });
  await db("credential_types").update({ catalog_hash: null, catalog_signature: null });
  await db("aura_rules").update({ rule_signature: null });
};

const waitForDbRow = async <T>(
  db: DbClient,
  query: () => Promise<T | null | undefined>,
  label: string,
  timeoutMs = 120_000,
  options?: { onTimeout?: () => Promise<void> | void; pollMs?: number }
) => {
  const start = Date.now();
  const pollMs = options?.pollMs ?? 2000;
  while (Date.now() - start < timeoutMs) {
    const result = await query();
    if (result) {
      return result;
    }
    await sleep(pollMs);
  }
  if (options?.onTimeout) {
    try {
      await options.onTimeout();
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      console.error(`[diag] onTimeout callback failed for ${label}: ${detail}`);
    }
  }
  throw new Error(`Timed out waiting for ${label}`);
};

const emitAnchorDiagnostics = async (db: DbClient, phase: string) => {
  console.log(`[diag] anchor phase timeout: ${phase}`);
  try {
    const response = await fetch(`${ISSUER_SERVICE_BASE_URL}/healthz`);
    const healthText = await response.text();
    console.log(`[diag] issuer /healthz: ${healthText}`);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.log(`[diag] issuer /healthz unavailable: ${detail}`);
  }
  try {
    const response = await fetch(`${ISSUER_SERVICE_BASE_URL}/metrics`);
    const metricsText = await response.text();
    const anchorLines = metricsText
      .split("\n")
      .filter(
        (line) =>
          line.includes("anchor_worker") ||
          line.includes("anchor_outbox") ||
          line.includes("worker_runs_total")
      )
      .slice(0, 60)
      .join("\n");
    console.log(`[diag] issuer anchor metrics\n${anchorLines}`);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.log(`[diag] issuer /metrics unavailable: ${detail}`);
  }
  const outboxByStatus = await db("anchor_outbox")
    .select("status")
    .count<{ status: string; count: string }>("outbox_id as count")
    .groupBy("status");
  const outboxByEventStatus = await db("anchor_outbox")
    .select("event_type", "status")
    .count<{ event_type: string; status: string; count: string }>("outbox_id as count")
    .groupBy("event_type", "status");
  const oldestProcessing = await db("anchor_outbox")
    .where({ status: "PROCESSING" })
    .orderBy("processing_started_at", "asc")
    .first();
  console.log(`[diag] anchor_outbox by status: ${JSON.stringify(outboxByStatus)}`);
  console.log(`[diag] anchor_outbox by event/status: ${JSON.stringify(outboxByEventStatus)}`);
  if (oldestProcessing) {
    console.log(
      `[diag] oldest processing row: ${JSON.stringify({
        outbox_id: oldestProcessing.outbox_id,
        event_type: oldestProcessing.event_type,
        attempts: oldestProcessing.attempts,
        processing_started_at: oldestProcessing.processing_started_at,
        updated_at: oldestProcessing.updated_at
      })}`
    );
  } else {
    console.log("[diag] no processing rows currently present");
  }
};

const emitServiceLogTail = (name: string, lastLines = 50) => {
  const rows = serviceLogTail.get(name) ?? [];
  const tail = rows.slice(Math.max(0, rows.length - lastLines));
  const payload = tail.length ? tail.join("\n") : "<no logs captured>";
  console.log(`[diag] ${name} log tail (last ${lastLines} lines)\n${payload}`);
};

const emitSocialTimeoutDiagnostics = async (db: DbClient, phase: string) => {
  console.log(`[diag] social timeout phase=${phase}`);
  await Promise.allSettled([
    emitHealthz("issuer-service", `${ISSUER_SERVICE_BASE_URL}/healthz`),
    emitHealthz("verifier-service", `${VERIFIER_SERVICE_BASE_URL}/healthz`),
    emitHealthz("policy-service", `${POLICY_SERVICE_BASE_URL}/healthz`),
    emitHealthz("social-service", `${SOCIAL_SERVICE_BASE_URL}/healthz`),
    emitMetricsExcerpt("issuer-service", `${ISSUER_SERVICE_BASE_URL}/metrics`, 80),
    emitMetricsExcerpt("verifier-service", `${VERIFIER_SERVICE_BASE_URL}/metrics`, 80),
    emitMetricsExcerpt("social-service", `${SOCIAL_SERVICE_BASE_URL}/metrics`, 80)
  ]);

  const anchorByStatus = await db("anchor_outbox")
    .select("status")
    .count<{ status: string; count: string }>("outbox_id as count")
    .groupBy("status");
  const anchorByEventStatus = await db("anchor_outbox")
    .select("event_type", "status")
    .count<{ event_type: string; status: string; count: string }>("outbox_id as count")
    .groupBy("event_type", "status");
  const anchorReceiptsCount = await db("anchor_receipts")
    .count<{ count: string }>("* as count")
    .first();
  const auraSignalsUnprocessed = await db("aura_signals")
    .whereNull("processed_at")
    .count<{ count: string }>("id as count")
    .first();
  const auraQueueByStatus = await db("aura_issuance_queue")
    .select("status")
    .count<{ status: string; count: string }>("* as count")
    .groupBy("status");
  const socialActionTail = await db("social_action_log")
    .select(
      "id",
      "subject_did_hash",
      "action_type",
      "decision",
      "policy_id",
      "policy_version",
      "created_at"
    )
    .orderBy("id", "desc")
    .limit(20)
    .catch(() => []);
  console.log(`[diag] anchor_outbox_by_status=${JSON.stringify(anchorByStatus)}`);
  console.log(`[diag] anchor_outbox_by_event_status=${JSON.stringify(anchorByEventStatus)}`);
  console.log(`[diag] anchor_receipts_count=${Number(anchorReceiptsCount?.count ?? 0)}`);
  console.log(
    `[diag] aura_signals_unprocessed_count=${Number(auraSignalsUnprocessed?.count ?? 0)}`
  );
  console.log(`[diag] aura_issuance_queue_by_status=${JSON.stringify(auraQueueByStatus)}`);
  console.log(`[diag] social_action_log_last20=${JSON.stringify(socialActionTail)}`);

  for (const serviceName of [
    "did-service",
    "policy-service",
    "issuer-service",
    "verifier-service",
    "social-service",
    "app-gateway"
  ]) {
    emitServiceLogTail(serviceName, 50);
  }
};

const run = async () => {
  // Harness-only self test for the retry classifier + retry policy (off by default).
  // This is intentionally network-free; it ensures deterministic failures do NOT retry.
  if (process.env.HARNESS_SELF_TEST_HEDERA_RETRY === "1") {
    let attempts = 0;
    let threwDeterministic = false;
    try {
      await runWithHederaRetries({
        label: "self_test_deterministic",
        maxAttempts: 3,
        fn: async () => {
          attempts += 1;
          throw {
            name: "ReceiptStatusError",
            message: "receipt for transaction 0.0.1@170.1 contained error status INVALID_SIGNATURE",
            status: "INVALID_SIGNATURE"
          };
        }
      });
    } catch (error) {
      threwDeterministic =
        error instanceof Error && error.message.startsWith("DETERMINISTIC_FAILURE:");
    }
    assert.equal(threwDeterministic, true, "self-test should fail deterministically");
    assert.equal(attempts, 1, "deterministic failures must not be retried");
    console.log("self_test_ok:hedra_retry_classifier");
    return;
  }

  await resolveBaseUrls();
  console.log(
    `Service base URLs: did=${DID_SERVICE_BASE_URL} issuer=${ISSUER_SERVICE_BASE_URL} verifier=${VERIFIER_SERVICE_BASE_URL} policy=${POLICY_SERVICE_BASE_URL} social=${SOCIAL_SERVICE_BASE_URL} gateway=${APP_GATEWAY_BASE_URL}`
  );
  const testRunId = randomUUID();
  const runStartedAt = new Date().toISOString();
  const verifierOrigin = new URL(GATEWAY_MODE ? APP_GATEWAY_BASE_URL : VERIFIER_SERVICE_BASE_URL)
    .origin;
  const gatewayOrigin = new URL(APP_GATEWAY_BASE_URL).origin;
  const policyRequirementsUrl = (
    action: string,
    options?: { spaceId?: string; origin?: string }
  ) => {
    const requirementsBase =
      GATEWAY_MODE || SOCIAL_MODE ? APP_GATEWAY_BASE_URL : POLICY_SERVICE_BASE_URL;
    const url = new URL("/v1/requirements", requirementsBase);
    url.searchParams.set("action", action);
    url.searchParams.set("verifier_origin", options?.origin ?? verifierOrigin);
    if (options?.spaceId) {
      url.searchParams.set("space_id", options.spaceId);
    }
    return url.toString();
  };
  const socialRequirementsUrl = (
    action: string,
    options?: { spaceId?: string; origin?: string }
  ) => {
    const url = new URL("/v1/social/requirements", APP_GATEWAY_BASE_URL);
    url.searchParams.set("action", action);
    url.searchParams.set("verifier_origin", options?.origin ?? gatewayOrigin);
    if (options?.spaceId) {
      url.searchParams.set("space_id", options.spaceId);
    }
    return url.toString();
  };
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
      "issuer:key_revoke",
      "issuer:anchor_reconcile"
    ]
  );
  const serviceTokenVerifier = await createServiceToken(
    SERVICE_JWT_AUDIENCE_VERIFIER,
    SERVICE_JWT_SECRET_VERIFIER,
    ["verifier:request_sign"]
  );
  const db = createDb(DATABASE_URL);

  await runMigrations(db);
  await cleanupDb(db);

  const ensureSocialSpacePolicyPack = async () => {
    const tableExists = await db.schema.hasTable("social_space_policy_packs");
    if (!tableExists) return;
    const computeActionPolicyHash = async (actionId: string) => {
      const policy = await db("policies")
        .where({ action_id: actionId, enabled: true })
        .orderBy("version", "desc")
        .first();
      if (!policy) return null;
      const logicRaw = policy.logic as unknown;
      const logic =
        typeof logicRaw === "string"
          ? (JSON.parse(logicRaw) as Record<string, unknown>)
          : (logicRaw as Record<string, unknown>);
      return hashCanonicalJson({
        policy_id: policy.policy_id,
        action_id: policy.action_id,
        version: policy.version,
        enabled: policy.enabled,
        logic
      });
    };
    const joinPolicyHash = await computeActionPolicyHash("social.space.join");
    const postPolicyHash = await computeActionPolicyHash("social.space.post.create");
    const moderatePolicyHash = await computeActionPolicyHash("social.space.moderate");
    const now = new Date().toISOString();
    const existing = await db("social_space_policy_packs")
      .where({ policy_pack_id: "space.default.v1" })
      .first();
    if (!existing) {
      await db("social_space_policy_packs").insert({
        policy_pack_id: "space.default.v1",
        display_name: "Default Space Pack v1",
        join_action_id: "social.space.join",
        post_action_id: "social.space.post.create",
        moderate_action_id: "social.space.moderate",
        visibility: "members",
        join_policy_hash: joinPolicyHash,
        post_policy_hash: postPolicyHash,
        moderate_policy_hash: moderatePolicyHash,
        pinned_policy_hash_join: joinPolicyHash,
        pinned_policy_hash_post: postPolicyHash,
        pinned_policy_hash_moderate: moderatePolicyHash,
        created_at: now,
        updated_at: now
      });
      return;
    }
    await db("social_space_policy_packs").where({ policy_pack_id: "space.default.v1" }).update({
      join_policy_hash: joinPolicyHash,
      post_policy_hash: postPolicyHash,
      moderate_policy_hash: moderatePolicyHash,
      pinned_policy_hash_join: joinPolicyHash,
      pinned_policy_hash_post: postPolicyHash,
      pinned_policy_hash_moderate: moderatePolicyHash,
      updated_at: now
    });
  };
  await ensureSocialSpacePolicyPack();

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
            formats: ["dc+sd-jwt", "di+bbs"],
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

  const ensureCustomerCapabilityFlowPolicy = async () => {
    // Test-only "privileged write" action gated by Aura capability VCs.
    // This is used by the customer-ready E2E flow block (no mocks; real OID4VCI/OID4VP).
    const actionId = "customer.social.privileged_write";
    const policyId = `${actionId}.v1`;
    const existing = await db("policies").where({ policy_id: policyId }).first();
    if (existing) return;
    const now = new Date().toISOString();
    await db("actions")
      .insert({
        action_id: actionId,
        description: "Customer E2E privileged write (Aura capability gated)",
        created_at: now,
        updated_at: now
      })
      .onConflict("action_id")
      .merge({
        description: "Customer E2E privileged write (Aura capability gated)",
        updated_at: now
      });
    await db("policies").insert({
      policy_id: policyId,
      action_id: actionId,
      version: 1,
      enabled: true,
      logic: JSON.stringify({
        binding: { mode: "kb-jwt", require: true },
        requirements: [
          {
            vct: "cuncta.social.can_post",
            issuer: { mode: "env", env: "ISSUER_DID" },
            disclosures: ["can_post", "tier"],
            predicates: [{ path: "can_post", op: "eq", value: true }],
            revocation: { required: true }
          }
        ],
        obligations: [{ type: "ANCHOR_EVENT", event: "VERIFY", when: "ON_ALLOW" }]
      }),
      created_at: now,
      updated_at: now
    });
  };

  await ensureCustomerCapabilityFlowPolicy();

  const runAuraWorkerOnce = async () => {
    // This harness may detect an invalid POLICY_SIGNING_JWK from a developer .env and generate a valid one.
    // For the in-process aura worker run, force the validated/generated key to be used.
    // Also force a non-production env so issuer config fail-closed checks don't pick up
    // unrelated developer NODE_ENV values during this in-process import path.
    process.env.NODE_ENV = "development";
    // issuer-service config expects ISSUER_BASE_URL; align in-process worker import env with spawned service config.
    process.env.ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? ISSUER_SERVICE_BASE_URL;
    process.env.POLICY_SIGNING_JWK = policySigningJwk;
    process.env.POLICY_SIGNING_BOOTSTRAP = "true";
    process.env.OID4VCI_TOKEN_SIGNING_JWK = "";
    process.env.OID4VCI_TOKEN_SIGNING_BOOTSTRAP = "true";
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
    AUTO_MIGRATE: "true",
    DEV_MODE: "true",
    ALLOW_INSECURE_DEV_AUTH: "false",
    SERVICE_JWT_SECRET,
    SERVICE_JWT_SECRET_DID,
    SERVICE_JWT_SECRET_ISSUER,
    SERVICE_JWT_SECRET_VERIFIER,
    SERVICE_JWT_SECRET_SOCIAL,
    ALLOW_LEGACY_SERVICE_JWT_SECRET: "false",
    SERVICE_JWT_AUDIENCE,
    SERVICE_JWT_AUDIENCE_DID,
    SERVICE_JWT_AUDIENCE_ISSUER,
    SERVICE_JWT_AUDIENCE_VERIFIER,
    SERVICE_JWT_AUDIENCE_SOCIAL,
    ISSUER_SERVICE_BASE_URL,
    VERIFIER_SERVICE_BASE_URL,
    POLICY_SERVICE_BASE_URL,
    SOCIAL_SERVICE_BASE_URL,
    APP_GATEWAY_BASE_URL,
    DID_SERVICE_BASE_URL,
    // Keep verifier DID resolution near-real-time in integration runs so rotation
    // authorization checks use fresh DID state and avoid stale-cache flakiness.
    DID_RESOLVE_CACHE_TTL_SECONDS: "1",
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
    ANCHOR_AUTH_SECRET: anchorAuthSecret,
    // ZK/age verification can exceed the app-gateway default 2.5s verifier proxy timeout.
    // Keep fail-closed behavior, but use a deterministic integration budget.
    VERIFIER_PROXY_TIMEOUT_MS: "15000",
    // Integration diagnostics: keep verifier/gateway denial reasons enabled.
    GATEWAY_VERIFY_DEBUG_REASONS: "true",
    VERIFIER_VERIFY_DEBUG_REASONS: "true",
    VERIFY_DEBUG_REASONS: "true",
    DEBUG_VERIFY_REASONS: "true"
  };

  const services: Record<string, ChildProcess> = {};

  try {
    if (GATEWAY_MODE && process.env.GATEWAY_MODE_FORCE_DIRECT === "1") {
      console.log("Forced failure: attempting direct DID create in gateway mode");
      await postJson(`${DID_SERVICE_BASE_URL}/v1/dids/create/request`, {});
    }
    const didProc = await ensureServiceRunning({
      name: "did-service",
      baseUrl: DID_SERVICE_BASE_URL,
      start: () =>
        startService("did-service", path.join(repoRoot, "apps", "did-service"), "src/index.ts", {
          ...baseEnv,
          PORT: String(DID_SERVICE_PORT)
        })
    });
    if (didProc) services.did = didProc;
    await waitForPortListening(DID_SERVICE_PORT);

    const policyProc = await ensureServiceRunning({
      name: "policy-service",
      baseUrl: POLICY_SERVICE_BASE_URL,
      start: () =>
        startService(
          "policy-service",
          path.join(repoRoot, "apps", "policy-service"),
          "src/index.ts",
          {
            ...baseEnv,
            PORT: String(POLICY_SERVICE_PORT)
          }
        )
    });
    if (policyProc) services.policy = policyProc;
    await waitForPortListening(POLICY_SERVICE_PORT);

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

    // The harness exercises OID4VCI/OID4VP flows via the app-gateway public surfaces,
    // even when not running in "gateway mode". Always start it unless explicitly disabled.
    const START_GATEWAY = process.env.START_GATEWAY !== "0";
    if (START_GATEWAY) {
      const gatewayProc = await ensureServiceRunning({
        name: "app-gateway",
        baseUrl: APP_GATEWAY_BASE_URL,
        start: () =>
          startService("app-gateway", path.join(repoRoot, "apps", "app-gateway"), "src/index.ts", {
            ...baseEnv,
            DID_SERVICE_BASE_URL,
            ISSUER_SERVICE_BASE_URL,
            VERIFIER_SERVICE_BASE_URL,
            POLICY_SERVICE_BASE_URL,
            SOCIAL_SERVICE_BASE_URL,
            APP_GATEWAY_BASE_URL,
            APP_GATEWAY_PUBLIC_BASE_URL: APP_GATEWAY_BASE_URL,
            PORT: String(APP_GATEWAY_PORT),
            GATEWAY_ALLOWED_VCTS:
              "cuncta.marketplace.seller_good_standing,cuncta.social.account_active,cuncta.social.can_post,cuncta.social.can_comment,cuncta.social.trusted_creator,cuncta.social.space.member,cuncta.social.space.poster,cuncta.social.space.moderator,cuncta.social.space.steward,cuncta.sync.scroll_host,cuncta.sync.listen_host,cuncta.sync.session_participant,cuncta.presence.mode_access,age_credential_v1",
            RATE_LIMIT_IP_DEFAULT_PER_MIN: "1000",
            RATE_LIMIT_IP_DID_REQUEST_PER_MIN: "200",
            RATE_LIMIT_IP_DID_SUBMIT_PER_MIN: "200",
            RATE_LIMIT_IP_ISSUE_PER_MIN: "200",
            RATE_LIMIT_IP_VERIFY_PER_MIN: "500",
            RATE_LIMIT_DEVICE_DID_PER_DAY: "50",
            RATE_LIMIT_DEVICE_ISSUE_PER_MIN: "200",
            ALLOW_SELF_FUNDED_ONBOARDING: "true",
            USER_PAYS_HANDOFF_SECRET: ensureUserPaysHandoffSecret(),
            SERVICE_JWT_SECRET_SOCIAL,
            SERVICE_JWT_AUDIENCE_SOCIAL
          })
      });
      if (gatewayProc) services.gateway = gatewayProc;
      await waitForPortListening(APP_GATEWAY_PORT);

      console.log("Sponsored endpoint returns 410 Gone");
      const sponsoredIssueRes = await fetch(`${APP_GATEWAY_BASE_URL}/v1/onboard/issue`, {
        method: "POST",
        headers: { "content-type": "application/json", ...gatewayHeaders() },
        body: JSON.stringify({
          subjectDid: "did:hedera:testnet:0.0.1",
          vct: "cuncta.marketplace.seller_good_standing",
          claims: {}
        })
      });
      assert.equal(sponsoredIssueRes.status, 410);
      const sponsoredIssueBody = (await sponsoredIssueRes.json().catch(() => ({}))) as {
        error?: string;
      };
      assert.equal(sponsoredIssueBody.error, "sponsored_onboarding_not_supported");
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
      // Prevent developer .env leakage from overriding bootstrap mode (common cause of Invalid keyData).
      OID4VCI_TOKEN_SIGNING_JWK: "",
      OID4VCI_TOKEN_SIGNING_BOOTSTRAP: "true",
      ISSUER_INTERNAL_ALLOWED_VCTS:
        "cuncta.marketplace.seller_good_standing,cuncta.social.account_active,cuncta.social.can_post,cuncta.social.can_comment,cuncta.social.trusted_creator,cuncta.social.space.member,cuncta.social.space.poster,cuncta.social.space.moderator,cuncta.social.space.steward,cuncta.sync.scroll_host,cuncta.sync.listen_host,cuncta.sync.session_participant,cuncta.presence.mode_access"
    };
    const verifierEnv = {
      ...baseEnv,
      ISSUER_DID: issuerDid,
      ISSUER_JWKS: "",
      STATUS_LIST_CACHE_TTL_SECONDS: process.env.STATUS_LIST_CACHE_TTL_SECONDS ?? "20",
      ENFORCE_DID_KEY_BINDING: "true",
      ENFORCE_ORIGIN_AUDIENCE: "true",
      // Prevent developer .env leakage from overriding bootstrap mode.
      VERIFIER_SIGNING_JWK: "",
      VERIFIER_SIGNING_BOOTSTRAP: "true",
      DID_SERVICE_BASE_URL
    };

    const issuerProc = await ensureServiceRunning({
      name: "issuer-service",
      baseUrl: ISSUER_SERVICE_BASE_URL,
      start: () =>
        startService(
          "issuer-service",
          path.join(repoRoot, "apps", "issuer-service"),
          "src/index.ts",
          {
            ...issuerEnv,
            PORT: String(ISSUER_SERVICE_PORT)
          }
        )
    });
    if (issuerProc) services.issuer = issuerProc;
    await waitForPortListening(ISSUER_SERVICE_PORT);

    const verifierProc = await ensureServiceRunning({
      name: "verifier-service",
      baseUrl: VERIFIER_SERVICE_BASE_URL,
      start: () =>
        startService(
          "verifier-service",
          path.join(repoRoot, "apps", "verifier-service"),
          "src/index.ts",
          {
            ...verifierEnv,
            PORT: String(VERIFIER_SERVICE_PORT)
          }
        )
    });
    if (verifierProc) services.verifier = verifierProc;
    await waitForPortListening(VERIFIER_SERVICE_PORT);

    await waitForHealth(`${ISSUER_SERVICE_BASE_URL}/healthz`);
    await waitForHealth(`${VERIFIER_SERVICE_BASE_URL}/healthz`);

    const noAdminScopeToken = await createServiceToken(
      SERVICE_JWT_AUDIENCE_ISSUER,
      SERVICE_JWT_SECRET_ISSUER,
      ["did:create_request"]
    );
    const adminRejectResponse = await fetch(
      `${ISSUER_SERVICE_BASE_URL}/v1/admin/anchors/reconcile`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          Authorization: `Bearer ${noAdminScopeToken}`
        },
        body: JSON.stringify({})
      }
    );
    const adminRejectBody = (await adminRejectResponse.json().catch(() => ({}))) as {
      error?: string;
    };
    assert.equal(adminRejectResponse.status, 403);
    assert.equal(adminRejectBody.error, "service_auth_scope_missing");

    if (SOCIAL_MODE) {
      services.social = startService(
        "social-service",
        path.join(repoRoot, "apps", "social-service"),
        "src/index.ts",
        {
          ...baseEnv,
          PORT: String(SOCIAL_SERVICE_PORT)
        }
      );
      await waitForHealth(`${SOCIAL_SERVICE_BASE_URL}/healthz`);
    }

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
    const policyResponse = await fetch(policyRequirementsUrl(tamperAction));
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
      }>(policyRequirementsUrl("marketplace.list_item"));
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
      `${ISSUER_SERVICE_BASE_URL}/v1/admin/keys/rotate`,
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
    const verifyRotation = await postJson<Record<string, unknown>>(
      `${verifyBaseUrlRotation}/v1/verify?action=marketplace.list_item`,
      {
        presentation: rotationPresentation,
        nonce: rotationRequirements.challenge.nonce,
        audience: rotationRequirements.challenge.audience
      }
    );
    if (String(verifyRotation.decision ?? "") !== "ALLOW") {
      console.log(
        `[diag] issuer_rotation_verify_meta=${JSON.stringify({
          step: currentIntegrationStep,
          action: "marketplace.list_item",
          audience: rotationRequirements.challenge.audience,
          nonce: rotationRequirements.challenge.nonce,
          holderDid,
          oldKid,
          newKid: rotateResponse.kid
        })}`
      );
      console.log(
        `[diag] issuer_rotation_vp_result=${JSON.stringify({
          event: "vp.respond.result",
          decision: verifyRotation.decision ?? null,
          reasons: verifyRotation.reasons ?? null
        })}`
      );
      console.log(`[diag] issuer_rotation_verify_raw=${JSON.stringify(verifyRotation)}`);
    }
    assert.equal(String(verifyRotation.decision ?? ""), "ALLOW");
    await postJson(
      `${ISSUER_SERVICE_BASE_URL}/v1/admin/keys/revoke`,
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

    console.log("Test 2: OID4VCI -> OID4VP (ALLOW)");
    const walletDir = path.join(repoRoot, ".tmp-wallet", `it-${testRunId}`);
    const walletEnvBase = {
      WALLET_DIR: walletDir,
      NODE_ENV: "development",
      WALLET_DEBUG_STACK: "1",
      // The DID rotation test needs access to the *old* signing key material to prove
      // DID<->cnf binding changes. Force the file keystore so the harness can read it
      // from `wallet-state.json` (DPAPI keystore won't expose private keys).
      WALLET_KEYSTORE: "file",
      ALLOW_INSECURE_WALLET_KEYS: "true",
      DID_SERVICE_BASE_URL,
      ISSUER_SERVICE_BASE_URL,
      POLICY_SERVICE_BASE_URL,
      VERIFIER_SERVICE_BASE_URL,
      APP_GATEWAY_BASE_URL,
      HEDERA_NETWORK: process.env.HEDERA_NETWORK ?? "testnet"
    };
    const walletEnvDidCreate = {
      ...walletEnvBase,
      // Force self-funded DID creation without going through gateway sponsor-budget enforcement.
      // Keeping `APP_GATEWAY_BASE_URL` unset here prevents wallet-cli from attempting gateway user-pays helpers.
      APP_GATEWAY_BASE_URL: "",
      // Phase 0: explicit payer creds, no operator-as-payer fallback.
      TESTNET_PAYER_ACCOUNT_ID:
        process.env.TESTNET_PAYER_ACCOUNT_ID ?? process.env.HEDERA_PAYER_ACCOUNT_ID ?? "",
      TESTNET_PAYER_PRIVATE_KEY:
        process.env.TESTNET_PAYER_PRIVATE_KEY ?? process.env.HEDERA_PAYER_PRIVATE_KEY ?? "",
      // wallet-cli currently resolves payer creds from HEDERA_PAYER_* env names.
      HEDERA_PAYER_ACCOUNT_ID:
        process.env.HEDERA_PAYER_ACCOUNT_ID ?? process.env.TESTNET_PAYER_ACCOUNT_ID ?? "",
      HEDERA_PAYER_PRIVATE_KEY:
        process.env.HEDERA_PAYER_PRIVATE_KEY ?? process.env.TESTNET_PAYER_PRIVATE_KEY ?? ""
    };
    const walletEnvVp = { ...walletEnvBase, APP_GATEWAY_BASE_URL };
    // Wallet creates its own DID/key material and persists to `.tmp-wallet/`.
    let didCreate = await runWalletCli(
      ["did:create:auto", "--mode", "user_pays"],
      walletEnvDidCreate
    );
    let didCreateDelayMs = 2000;
    for (let attempt = 1; attempt <= 3 && didCreate.exitCode !== 0; attempt += 1) {
      console.log(`[diag] wallet_did_create_retry attempt=${attempt} delayMs=${didCreateDelayMs}`);
      await sleep(didCreateDelayMs);
      didCreateDelayMs = Math.min(15_000, Math.round(didCreateDelayMs * 1.8));
      didCreate = await runWalletCli(
        ["did:create:auto", "--mode", "user_pays"],
        walletEnvDidCreate
      );
    }
    assert.equal(didCreate.exitCode, 0, didCreate.stderr || didCreate.stdout);

    {
      console.log("Test 2-rotate: DID rotation updates DID↔cnf binding");
      const walletStatePath = path.join(walletDir, "wallet-state.json");
      const beforeRotate = JSON.parse(await readFile(walletStatePath, "utf8")) as any;
      const walletDid = String(beforeRotate?.did?.did ?? "");
      assert.ok(walletDid.startsWith("did:"));
      const readKeyMaterial = (state: any, purpose: "holder" | "primary") => {
        const fromKeystore =
          purpose === "primary" ? state?.keystore?.ed25519 : state?.keystore?.holder_ed25519;
        if (fromKeystore?.privateKeyBase64 && fromKeystore?.publicKeyBase64) {
          return {
            privateKeyBase64: String(fromKeystore.privateKeyBase64),
            publicKeyBase64: String(fromKeystore.publicKeyBase64)
          };
        }
        // Backward compat: older wallets may have written raw keys to `keys.ed25519`.
        const legacy = state?.keys?.ed25519;
        if (legacy?.privateKeyBase64 && legacy?.publicKeyBase64) {
          return {
            privateKeyBase64: String(legacy.privateKeyBase64),
            publicKeyBase64: String(legacy.publicKeyBase64)
          };
        }
        throw new Error(`wallet_${purpose}_private_key_missing (expected WALLET_KEYSTORE=file)`);
      };
      const beforeKeys = readKeyMaterial(beforeRotate, "holder");
      const oldPriv = Buffer.from(beforeKeys.privateKeyBase64, "base64");
      const oldPub = Buffer.from(beforeKeys.publicKeyBase64, "base64");
      const oldJwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: toBase64Url(oldPub),
        d: toBase64Url(oldPriv),
        alg: "EdDSA",
        kid: `holder-old-${testRunId}`
      };
      const oldCryptoKey = await importJWK(oldJwk as never, "EdDSA");
      const rotate = await runWalletCli(["did:rotate"], walletEnvDidCreate);
      assert.equal(rotate.exitCode, 0, rotate.stderr || rotate.stdout);
      const afterRotate = JSON.parse(await readFile(walletStatePath, "utf8")) as any;
      const afterKeys = readKeyMaterial(afterRotate, "holder");
      const newPriv = Buffer.from(afterKeys.privateKeyBase64, "base64");
      const newPub = Buffer.from(afterKeys.publicKeyBase64, "base64");
      const newJwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: toBase64Url(newPub),
        d: toBase64Url(newPriv),
        alg: "EdDSA",
        kid: `holder-new-${testRunId}`
      };
      const expectedNewPublicKeyMultibase = String(
        afterRotate?.keys?.holder?.publicKeyMultibase ??
          afterRotate?.keystore?.holder_ed25519?.publicKeyMultibase ??
          ""
      );
      const expectedOldPublicKeyMultibase = String(
        beforeRotate?.keys?.holder?.publicKeyMultibase ??
          beforeRotate?.keystore?.holder_ed25519?.publicKeyMultibase ??
          ""
      );
      const newPublicJwk = {
        kty: "OKP",
        crv: "Ed25519",
        x: newJwk.x,
        alg: "EdDSA",
        kid: newJwk.kid
      };
      const newCryptoKey = await importJWK(newJwk as never, "EdDSA");

      // Wait until rotation is fully visible in the DID document (mirror propagation):
      // new holder key present AND old holder key no longer authorized.
      {
        const maxAttempts = DID_ROTATION_VISIBILITY_ATTEMPTS;
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
          const resolved = await requestJson<{ didDocument?: Record<string, unknown> }>(
            `${DID_SERVICE_BASE_URL}/v1/dids/resolve/${encodeURIComponent(walletDid)}`
          ).catch(() => ({ didDocument: undefined }));
          const methods = Array.isArray(resolved.didDocument?.verificationMethod)
            ? (resolved.didDocument?.verificationMethod as Array<Record<string, unknown>>)
            : [];
          const hasNew = methods.some((m) => {
            const multibase = (m as any).publicKeyMultibase;
            if (expectedNewPublicKeyMultibase && multibase === expectedNewPublicKeyMultibase) {
              return true;
            }
            const jwk = (m as any).publicKeyJwk;
            return Boolean(jwk && typeof jwk === "object" && (jwk as any).x === newPublicJwk.x);
          });
          const hasOld = methods.some((m) => {
            const multibase = (m as any).publicKeyMultibase;
            if (expectedOldPublicKeyMultibase && multibase === expectedOldPublicKeyMultibase) {
              return true;
            }
            const jwk = (m as any).publicKeyJwk;
            return Boolean(jwk && typeof jwk === "object" && (jwk as any).x === oldJwk.x);
          });
          if (hasNew && !hasOld) break;
          if (attempt === maxAttempts) {
            throw new Error("did_rotation_visibility_timeout:new_present_and_old_removed");
          }
          await sleep(DID_ROTATION_VISIBILITY_INTERVAL_MS);
        }
      }

      // Issue a credential for the rotated DID and prove old vs new key binding behavior.
      const rotateRequirements = await requestJson<{
        challenge: { nonce: string; audience: string };
        requirements: Array<{
          vct: string;
          disclosures?: string[];
          predicates?: Array<{ path: string; op: string; value?: unknown }>;
        }>;
      }>(policyRequirementsUrl("marketplace.list_item", { origin: verifierOrigin }));
      const rotateReq = rotateRequirements.requirements[0];
      assert.ok(rotateReq);
      const rotateIssue = await issueCredentialFor({
        subjectDid: walletDid,
        vct: rotateReq.vct,
        claims: buildClaimsFromRequirements(rotateReq)
      });
      const rotateDisclosureList = buildDisclosureList(rotateReq);
      const verifyBaseUrlRotate = GATEWAY_MODE ? APP_GATEWAY_BASE_URL : VERIFIER_SERVICE_BASE_URL;

      // Authoritative finality gate: poll the same verifier path used at runtime until
      // old holder key is rejected for DID<->cnf binding.
      let verifyOld: VerifyResponse | null = null;
      {
        const maxAttempts = DID_ROTATION_VISIBILITY_ATTEMPTS;
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
          const rotateProbeReq = await requestJson<{
            challenge: { nonce: string; audience: string };
          }>(policyRequirementsUrl("marketplace.list_item", { origin: verifierOrigin }));
          const oldProbePresentation = await buildPresentation({
            sdJwt: rotateIssue.credential,
            disclose: rotateDisclosureList,
            nonce: rotateProbeReq.challenge.nonce,
            audience: rotateProbeReq.challenge.audience,
            holderJwk: { kty: "OKP", crv: "Ed25519", x: oldJwk.x, alg: "EdDSA", kid: oldJwk.kid },
            holderKey: oldCryptoKey
          });
          verifyOld = await postJson<VerifyResponse>(
            `${verifyBaseUrlRotate}/v1/verify?action=marketplace.list_item`,
            {
              presentation: oldProbePresentation,
              nonce: rotateProbeReq.challenge.nonce,
              audience: rotateProbeReq.challenge.audience
            }
          );
          const deniedByDidBinding =
            verifyOld.decision === "DENY" &&
            (!INCLUDE_VERIFY_REASONS ||
              Boolean(verifyOld.reasons?.includes("did_key_not_authorized")));
          if (deniedByDidBinding) break;
          if (attempt === maxAttempts) {
            throw new Error(
              `did_rotation_old_key_still_authorized:last=${JSON.stringify(verifyOld)}`
            );
          }
          await sleep(DID_ROTATION_VISIBILITY_INTERVAL_MS);
        }
      }
      assert.ok(verifyOld);
      assert.equal(verifyOld.decision, "DENY");
      if (INCLUDE_VERIFY_REASONS) {
        assert.ok(verifyOld.reasons?.includes("did_key_not_authorized"));
      }
      const rotateRequirements2 = await requestJson<{
        challenge: { nonce: string; audience: string };
      }>(policyRequirementsUrl("marketplace.list_item", { origin: verifierOrigin }));
      const presentationNew = await buildPresentation({
        sdJwt: rotateIssue.credential,
        disclose: rotateDisclosureList,
        nonce: rotateRequirements2.challenge.nonce,
        audience: rotateRequirements2.challenge.audience,
        holderJwk: newPublicJwk as any,
        holderKey: newCryptoKey
      });
      const verifyNew = await postJson<VerifyResponse>(
        `${verifyBaseUrlRotate}/v1/verify?action=marketplace.list_item`,
        {
          presentation: presentationNew,
          nonce: rotateRequirements2.challenge.nonce,
          audience: rotateRequirements2.challenge.audience
        }
      );
      assert.equal(verifyNew.decision, "ALLOW");
    }

    const oidReq = await requestJson<{
      action: string;
      nonce: string;
      audience: string;
      expires_at: string;
      requirements: Array<{
        vct: string;
        disclosures?: string[];
        predicates?: Array<{ path: string; op: string; value?: unknown }>;
      }>;
    }>(
      `${APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent(
        "marketplace.list_item"
      )}&verifier_origin=${encodeURIComponent(verifierOrigin)}`
    );
    const oidRequirement = oidReq.requirements[0];
    assert.ok(oidRequirement);

    console.log("Test 2a: OID4VCI negative grant validation");
    // /token without pre-authorized_code must fail.
    {
      const meta = await requestJson<{ token_endpoint: string }>(
        `${ISSUER_SERVICE_BASE_URL}/.well-known/openid-credential-issuer`
      );
      const noCodeRes = await fetch(meta.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        }).toString()
      });
      assert.ok(!noCodeRes.ok, "token without preauth must fail");
    }
    // Redeeming a pre-authorized code twice must fail (one-time semantics).
    {
      const offer = await requestJson<any>(
        `${APP_GATEWAY_BASE_URL}/oid4vci/offer?vct=${encodeURIComponent(oidRequirement.vct)}`
      );
      const configId = String(offer?.credential_offer?.credential_configuration_ids?.[0] ?? "");
      assert.ok(configId.length > 3, "offer must include credential_configuration_id");
      const preauth =
        offer?.credential_offer?.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"]?.[
          "pre-authorized_code"
        ];
      assert.ok(
        typeof preauth === "string" && preauth.length > 10,
        "offer must include preauth code"
      );
      const meta = await requestJson<{ token_endpoint: string }>(
        `${ISSUER_SERVICE_BASE_URL}/.well-known/openid-credential-issuer`
      );
      const once = await fetch(meta.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": preauth
        }).toString()
      });
      assert.ok(once.ok, "first redemption should succeed");
      const twice = await fetch(meta.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": preauth
        }).toString()
      });
      assert.ok(!twice.ok, "second redemption must fail (replay)");
    }
    console.log("Test 2b: OID4VCI negative proof enforcement");
    {
      const offer = await requestJson<any>(
        `${APP_GATEWAY_BASE_URL}/oid4vci/offer?vct=${encodeURIComponent(oidRequirement.vct)}`
      );
      const configId = String(offer?.credential_offer?.credential_configuration_ids?.[0] ?? "");
      assert.ok(configId.length > 3, "offer must include credential_configuration_id");
      const preauth =
        offer?.credential_offer?.grants?.["urn:ietf:params:oauth:grant-type:pre-authorized_code"]?.[
          "pre-authorized_code"
        ];
      assert.ok(typeof preauth === "string" && preauth.length > 10);
      const meta = await requestJson<{ token_endpoint: string; credential_endpoint: string }>(
        `${ISSUER_SERVICE_BASE_URL}/.well-known/openid-credential-issuer`
      );
      const tokenRes = await fetch(meta.token_endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code": preauth
        }).toString()
      });
      assert.ok(tokenRes.ok);
      const tokenJson = (await tokenRes.json()) as { access_token?: string };
      assert.ok(typeof tokenJson.access_token === "string" && tokenJson.access_token.length > 10);
      const credentialRes = await fetch(meta.credential_endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${tokenJson.access_token}`
        },
        body: JSON.stringify({
          subjectDid: holderDid,
          credential_configuration_id: configId,
          format: "dc+sd-jwt",
          claims: buildClaimsFromRequirements(oidRequirement)
        })
      });
      assert.ok(!credentialRes.ok, "/credential without proof must fail");
    }
    const claimsPath = await writeJsonArgFile(
      walletDir,
      "oid4vci-claims",
      buildClaimsFromRequirements(oidRequirement)
    );
    const acquire = await runWalletCli(
      [
        "vc:acquire",
        "--issuer",
        ISSUER_SERVICE_BASE_URL,
        "--config-id",
        oidRequirement.vct,
        "--claims-json",
        `@${claimsPath}`
      ],
      walletEnvBase
    );
    assert.equal(acquire.exitCode, 0, acquire.stderr || acquire.stdout);
    const oidReqPath = await writeJsonArgFile(walletDir, "oid4vp-request", oidReq);
    const respond = await runWalletCli(["vp:respond", "--request", `@${oidReqPath}`], walletEnvVp);
    assert.equal(respond.exitCode, 0, respond.stderr || respond.stdout);
    const oidVerify = parseLastJsonFromStdout(respond.stdout) as { decision?: string } | null;
    assert.ok(oidVerify);
    if (oidVerify?.decision !== "ALLOW") {
      const requestJwt =
        typeof oidReq?.request_jwt === "string" && oidReq.request_jwt.trim().length
          ? oidReq.request_jwt.trim()
          : "";
      const decodedRequest = requestJwt ? (decodeJwt(requestJwt) as Record<string, unknown>) : {};
      console.log(`[diag] oid4vp_unexpected_decision decision=${oidVerify?.decision ?? "null"}`);
      console.log(
        `[diag] oid4vp_unexpected_decision_meta=${JSON.stringify({
          step: currentIntegrationStep,
          verify: oidVerify,
          request: {
            action: oidReq?.action ?? null,
            nonce: oidReq?.nonce ?? null,
            audience: oidReq?.audience ?? null,
            client_id: oidReq?.client_id ?? null,
            response_uri: oidReq?.response_uri ?? null,
            policy_hash: decodedRequest.policy_hash ?? null,
            action_id: decodedRequest.action_id ?? null
          },
          holderDid: walletDid
        })}`
      );
      console.log(`[diag] oid4vp_wallet_stdout=${respond.stdout.trim()}`);
      if (respond.stderr.trim()) {
        console.log(`[diag] oid4vp_wallet_stderr=${respond.stderr.trim()}`);
      }
    }
    assert.equal(oidVerify?.decision, "ALLOW");

    console.log("Test 2d: OID4VCI DI+BBS -> OID4VP (ALLOW)");
    {
      // Each OID4VP request can be consumed once (hash store); fetch a fresh one for this subtest.
      const oidReqDi = await requestJson<any>(
        `${APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent(
          "marketplace.list_item"
        )}&verifier_origin=${encodeURIComponent(verifierOrigin)}`
      );
      const diOffer = await requestJson<any>(
        `${APP_GATEWAY_BASE_URL}/oid4vci/offer?vct=${encodeURIComponent(oidRequirement.vct)}&format=${encodeURIComponent(
          "di+bbs"
        )}`
      );
      const diOfferPath = await writeJsonArgFile(walletDir, "oid4vci-offer-di", diOffer);
      const claimsDiPath = await writeJsonArgFile(
        walletDir,
        "oid4vci-claims-di",
        buildClaimsFromRequirements(oidRequirement)
      );
      const acquireDi = await runWalletCli(
        [
          "vc:acquire",
          "--issuer",
          ISSUER_SERVICE_BASE_URL,
          "--config-id",
          oidRequirement.vct,
          "--offer",
          `@${diOfferPath}`,
          "--format",
          "di+bbs",
          "--claims-json",
          `@${claimsDiPath}`
        ],
        walletEnvBase
      );
      assert.equal(acquireDi.exitCode, 0, acquireDi.stderr || acquireDi.stdout);
      const oidReqDiPath = await writeJsonArgFile(walletDir, "oid4vp-request-di", oidReqDi);
      const respondDi = await runWalletCli(["vp:respond", "--request", `@${oidReqDiPath}`], {
        ...walletEnvVp,
        WALLET_PREFER_DI_BBS: "1"
      });
      assert.equal(respondDi.exitCode, 0, respondDi.stderr || respondDi.stdout);
      const diVerify = parseLastJsonFromStdout(respondDi.stdout) as { decision?: string } | null;
      assert.ok(diVerify);
      if (diVerify?.decision !== "ALLOW") {
        console.log(
          `[diag] oid4vp_di_unexpected_decision decision=${diVerify?.decision ?? "null"}`
        );
        console.log(`[diag] oid4vp_di_wallet_stdout=${respondDi.stdout.trim()}`);
        if (respondDi.stderr.trim()) {
          console.log(`[diag] oid4vp_di_wallet_stderr=${respondDi.stderr.trim()}`);
        }
      }
      assert.equal(diVerify?.decision, "ALLOW");
    }

    console.log(
      "Test 2e: OID4VCI age_credential_v1 (commitment-only) -> OID4VP ZK age>=18 (ALLOW)"
    );
    const adultBirthdateDays =
      typeof process.env.WALLET_BIRTHDATE_DAYS === "string" &&
      process.env.WALLET_BIRTHDATE_DAYS.trim().length
        ? Number(process.env.WALLET_BIRTHDATE_DAYS)
        : Math.floor(Date.now() / 86_400_000) - 20 * 365;

    const acquireAge = await runWalletCli(
      ["vc:acquire", "--issuer", ISSUER_SERVICE_BASE_URL, "--config-id", "age_credential_v1"],
      { ...walletEnvBase, WALLET_BIRTHDATE_DAYS: String(adultBirthdateDays) }
    );
    assert.equal(acquireAge.exitCode, 0, acquireAge.stderr || acquireAge.stdout);

    const datingReq = await requestJson<any>(
      `${APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent("dating_enter")}&verifier_origin=${encodeURIComponent(
        verifierOrigin
      )}`
    );
    // Prove + verify via gateway (direct_post.jwt)
    const datingReqPath = await writeJsonArgFile(walletDir, "oid4vp-request-dating", datingReq);
    const respondDating = await runWalletCli(
      ["vp:respond", "--request", `@${datingReqPath}`],
      walletEnvVp
    );
    assert.equal(respondDating.exitCode, 0, respondDating.stderr || respondDating.stdout);
    const datingVerify = parseLastJsonFromStdout(respondDating.stdout) as {
      decision?: string;
    } | null;
    assert.ok(datingVerify);
    let datingDiag = "";
    if (datingVerify?.decision !== "ALLOW") {
      const challengeNonce =
        typeof datingReq?.nonce === "string"
          ? datingReq.nonce
          : ((datingReq?.challenge?.nonce as string | undefined) ?? "");
      const challengeHash = sha256Hex(challengeNonce);
      const challengeRow = await db("verification_challenges")
        .where({ challenge_hash: challengeHash })
        .first();
      const policyRow =
        challengeRow?.policy_id && challengeRow?.policy_version
          ? await db("policies")
              .where({
                policy_id: String(challengeRow.policy_id),
                version: Number(challengeRow.policy_version)
              })
              .first()
          : null;
      datingDiag = JSON.stringify({
        challengeNonceLength: challengeNonce.length,
        challengeHash,
        challengePolicyId: challengeRow?.policy_id ?? null,
        challengePolicyVersion: challengeRow?.policy_version ?? null,
        challengePolicyHash: challengeRow?.policy_hash ?? null,
        policyRowHash: policyRow?.policy_hash ?? null,
        policySignaturePresent: Boolean(policyRow?.policy_signature),
        policyEnabled: policyRow?.enabled ?? null
      });
    }
    assert.equal(
      datingVerify?.decision,
      "ALLOW",
      `dating_enter_expected_allow got=${JSON.stringify(datingVerify)} stdoutTail=${JSON.stringify(
        tailLines(respondDating.stdout, 40)
      )} stderrTail=${JSON.stringify(tailLines(respondDating.stderr, 40))} diag=${datingDiag}`
    );

    console.log("Test 2e-neg1: wrong nonce/audience/request_hash bindings DENY");
    const datingReq2 = await requestJson<any>(
      `${APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent("dating_enter")}&verifier_origin=${encodeURIComponent(
        verifierOrigin
      )}`
    );
    const datingReq2Path = await writeJsonArgFile(
      walletDir,
      "oid4vp-request-dating-neg1",
      datingReq2
    );
    const emit = await runWalletCli(
      ["vp:respond", "--emit-response-jwt", "--request", `@${datingReq2Path}`],
      { ...walletEnvVp, ISSUER_SERVICE_BASE_URL, WALLET_BIRTHDATE_DAYS: String(adultBirthdateDays) }
    );
    assert.equal(emit.exitCode, 0, emit.stderr || emit.stdout);
    const emitted = parseLastJsonFromStdout(emit.stdout) as { response_jwt?: string } | null;
    assert.ok(emitted?.response_jwt);
    const decoded = decodeJwt(emitted!.response_jwt!) as any;
    const correct = await postJson<VerifyResponse>(`${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`, {
      action: "dating_enter",
      presentation: String(decoded.vp_token),
      nonce: String((decodeJwt(String(decoded.request)) as any).nonce),
      audience: String((decodeJwt(String(decoded.request)) as any).audience),
      requestHash: sha256Hex(String(decoded.request)),
      requestJwt: String(decoded.request),
      zk_proofs: decoded.zk_proofs
    });
    assert.equal(correct.decision, "ALLOW");

    const wrongNonce = await postJson<VerifyResponse>(
      `${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`,
      {
        action: "dating_enter",
        presentation: String(decoded.vp_token),
        nonce: "wrong-nonce",
        audience: String((decodeJwt(String(decoded.request)) as any).audience),
        requestHash: sha256Hex(String(decoded.request)),
        requestJwt: String(decoded.request),
        zk_proofs: decoded.zk_proofs
      }
    );
    assert.equal(wrongNonce.decision, "DENY");

    const wrongAud = await postJson<VerifyResponse>(
      `${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`,
      {
        action: "dating_enter",
        presentation: String(decoded.vp_token),
        nonce: String((decodeJwt(String(decoded.request)) as any).nonce),
        audience: "origin:https://evil.local",
        requestHash: sha256Hex(String(decoded.request)),
        requestJwt: String(decoded.request),
        zk_proofs: decoded.zk_proofs
      }
    );
    assert.equal(wrongAud.decision, "DENY");

    const wrongHash = await postJson<VerifyResponse>(
      `${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`,
      {
        action: "dating_enter",
        presentation: String(decoded.vp_token),
        nonce: String((decodeJwt(String(decoded.request)) as any).nonce),
        audience: String((decodeJwt(String(decoded.request)) as any).audience),
        requestHash: "00" + sha256Hex(String(decoded.request)).slice(2),
        requestJwt: String(decoded.request),
        zk_proofs: decoded.zk_proofs
      }
    );
    assert.equal(wrongHash.decision, "DENY");

    console.log("Test 2e-neg1b: mutated public signal (same proof) DENY");
    {
      const mutated = JSON.parse(JSON.stringify(decoded.zk_proofs)) as any[];
      mutated[0].public_signals[0] = "1"; // dob_commitment mismatch
      const res = await postJson<VerifyResponse>(`${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`, {
        action: "dating_enter",
        presentation: String(decoded.vp_token),
        nonce: String((decodeJwt(String(decoded.request)) as any).nonce),
        audience: String((decodeJwt(String(decoded.request)) as any).audience),
        requestHash: sha256Hex(String(decoded.request)),
        requestJwt: String(decoded.request),
        zk_proofs: mutated
      });
      assert.equal(res.decision, "DENY");
    }

    console.log("Test 2e-neg1c: swapped signal order (same proof) DENY");
    {
      const swapped = JSON.parse(JSON.stringify(decoded.zk_proofs)) as any[];
      const s = swapped[0].public_signals as string[];
      swapped[0].public_signals = [s[1], s[0], ...s.slice(2)];
      const res = await postJson<VerifyResponse>(`${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`, {
        action: "dating_enter",
        presentation: String(decoded.vp_token),
        nonce: String((decodeJwt(String(decoded.request)) as any).nonce),
        audience: String((decodeJwt(String(decoded.request)) as any).audience),
        requestHash: sha256Hex(String(decoded.request)),
        requestJwt: String(decoded.request),
        zk_proofs: swapped
      });
      assert.equal(res.decision, "DENY");
    }

    console.log("Test 2e-neg1d: min_age mismatch (same proof) DENY");
    {
      const mismatched = JSON.parse(JSON.stringify(decoded.zk_proofs)) as any[];
      mismatched[0].public_signals[1] = "21";
      const res = await postJson<VerifyResponse>(`${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`, {
        action: "dating_enter",
        presentation: String(decoded.vp_token),
        nonce: String((decodeJwt(String(decoded.request)) as any).nonce),
        audience: String((decodeJwt(String(decoded.request)) as any).audience),
        requestHash: sha256Hex(String(decoded.request)),
        requestJwt: String(decoded.request),
        zk_proofs: mismatched
      });
      assert.equal(res.decision, "DENY");
    }

    console.log("Test 2e-neg1e: stale current_day beyond drift window DENY");
    {
      const serverDay = Math.floor(Date.now() / 86_400_000);
      const staleDay = serverDay - 10;
      const nonce = `nonce-${randomUUID()}`;
      const audience = `origin:${verifierOrigin}`;
      const exp = Math.floor(Date.now() / 1000) + 300;
      const signPayload = await postJson<{ request_jwt?: string }>(
        `${VERIFIER_SERVICE_BASE_URL}/v1/request/sign`,
        {
          nonce,
          audience,
          exp,
          action_id: "dating_enter",
          policyHash: "deadbeef".repeat(8),
          iss: APP_GATEWAY_BASE_URL.replace(/\/$/, ""),
          state: randomUUID(),
          response_uri: `${APP_GATEWAY_BASE_URL.replace(/\/$/, "")}/oid4vp/response`,
          response_mode: "direct_post.jwt",
          response_type: "vp_token",
          client_id: verifierOrigin,
          client_id_scheme: "redirect_uri",
          presentation_definition: datingReq.presentation_definition,
          zk_context: { current_day: staleDay }
        },
        { Authorization: `Bearer ${serviceTokenVerifier}` }
      );
      assert.ok(signPayload.request_jwt, "request_jwt missing from signer");
      const staleReq = {
        ...datingReq,
        nonce,
        audience,
        expires_at: new Date(Date.now() + 120_000).toISOString(),
        request_jwt: signPayload.request_jwt,
        request_uri: undefined,
        zk_context: { current_day: staleDay }
      };
      const staleReqPath = await writeJsonArgFile(
        walletDir,
        "oid4vp-request-dating-stale",
        staleReq
      );
      const emitStale = await runWalletCli(
        ["vp:respond", "--emit-response-jwt", "--request", `@${staleReqPath}`],
        { ...walletEnvVp, WALLET_BIRTHDATE_DAYS: String(adultBirthdateDays) }
      );
      assert.equal(emitStale.exitCode, 0, emitStale.stderr || emitStale.stdout);
      const emittedStale = parseLastJsonFromStdout(emitStale.stdout) as {
        response_jwt?: string;
      } | null;
      assert.ok(emittedStale?.response_jwt);
      const dec = decodeJwt(emittedStale!.response_jwt!) as any;
      const res = await postJson<VerifyResponse>(`${VERIFIER_SERVICE_BASE_URL}/oid4vp/response`, {
        action: "dating_enter",
        presentation: String(dec.vp_token),
        nonce: String((decodeJwt(String(dec.request)) as any).nonce),
        audience: String((decodeJwt(String(dec.request)) as any).audience),
        requestHash: sha256Hex(String(dec.request)),
        requestJwt: String(dec.request),
        zk_proofs: dec.zk_proofs
      });
      assert.equal(res.decision, "DENY");
    }

    console.log("Test 2e-neg2: underage cannot satisfy proof");
    const underageBirthdateDays = Math.floor(Date.now() / 86_400_000) - 10 * 365;
    const underWalletDir = `${walletDir}-under`;
    const underDidCreate = await runWalletCli(["did:create:auto", "--mode", "user_pays"], {
      ...walletEnvDidCreate,
      WALLET_DIR: underWalletDir,
      WALLET_BIRTHDATE_DAYS: String(underageBirthdateDays)
    });
    assert.equal(underDidCreate.exitCode, 0, underDidCreate.stderr || underDidCreate.stdout);
    const acquireUnder = await runWalletCli(
      ["vc:acquire", "--issuer", ISSUER_SERVICE_BASE_URL, "--config-id", "age_credential_v1"],
      {
        ...walletEnvBase,
        WALLET_BIRTHDATE_DAYS: String(underageBirthdateDays),
        WALLET_DIR: underWalletDir
      }
    );
    assert.equal(acquireUnder.exitCode, 0, acquireUnder.stderr || acquireUnder.stdout);
    const datingReqUnder = await requestJson<any>(
      `${APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent("dating_enter")}&verifier_origin=${encodeURIComponent(
        verifierOrigin
      )}`
    );
    const datingReqUnderPath = await writeJsonArgFile(
      underWalletDir,
      "oid4vp-request-dating-under",
      datingReqUnder
    );
    const emitUnder = await runWalletCli(
      ["vp:respond", "--emit-response-jwt", "--request", `@${datingReqUnderPath}`],
      {
        ...walletEnvVp,
        WALLET_BIRTHDATE_DAYS: String(underageBirthdateDays),
        WALLET_DIR: underWalletDir
      }
    );
    assert.ok(emitUnder.exitCode !== 0, "underage should fail to produce a valid proof");

    console.log("Test 2e-neg3: revoke age credential -> subsequent verify DENY");
    const adultWalletStateRaw = await readFile(path.join(walletDir, "wallet-state.json"), "utf8");
    const adultWalletState = JSON.parse(adultWalletStateRaw) as {
      credentials?: Array<{ vct: string; credential: string }>;
    };
    const ageCred = (adultWalletState.credentials ?? []).find((c) => c.vct === "age_credential_v1");
    assert.ok(ageCred?.credential, "age credential missing from wallet state");
    const ageJwt = String(ageCred!.credential).split("~")[0];
    const agePayload = decodeJwt(ageJwt) as any;
    const status = agePayload.status ?? {};
    const statusListCredential = String(status.statusListCredential ?? "");
    const statusListIndex = Number(status.statusListIndex ?? NaN);
    assert.ok(
      statusListCredential.includes("/status-lists/"),
      "unexpected statusListCredential shape"
    );
    assert.ok(Number.isInteger(statusListIndex) && statusListIndex >= 0, "missing statusListIndex");
    const statusListId = statusListCredential.split("/").filter(Boolean).pop() as string;

    await postJson(
      `${ISSUER_SERVICE_BASE_URL}/v1/credentials/revoke`,
      { statusListId, statusListIndex },
      { Authorization: `Bearer ${serviceTokenIssuer}` }
    );

    const revokedStartedAt = Date.now();
    let revokedSatisfied = false;
    let replayCandidateReq: unknown = null;
    while (Date.now() - revokedStartedAt < 180_000) {
      const reqAfter = await requestJson<any>(
        `${APP_GATEWAY_BASE_URL}/oid4vp/request?action=${encodeURIComponent("dating_enter")}&verifier_origin=${encodeURIComponent(
          verifierOrigin
        )}`
      );
      replayCandidateReq = reqAfter;
      const reqAfterPath = await writeJsonArgFile(walletDir, "oid4vp-request-after", reqAfter);
      const respAfter = await runWalletCli(
        ["vp:respond", "--request", `@${reqAfterPath}`],
        walletEnvVp
      );
      assert.equal(respAfter.exitCode, 0, respAfter.stderr || respAfter.stdout);
      const verifyAfter = parseLastJsonFromStdout(respAfter.stdout) as { decision?: string } | null;
      assert.ok(verifyAfter);
      if (verifyAfter.decision === "DENY") {
        revokedSatisfied = true;
        break;
      }
      await sleep(5_000);
    }
    assert.ok(revokedSatisfied, "revocation should propagate within 3 minutes");

    console.log("Test 2c: OID4VP request replay fails (one-time request hash)");
    assert.ok(replayCandidateReq, "replay candidate request missing");
    const replayReqPath = await writeJsonArgFile(
      walletDir,
      "oid4vp-request-replay",
      replayCandidateReq
    );
    const respondReplay = await runWalletCli(
      ["vp:respond", "--request", `@${replayReqPath}`],
      walletEnvVp
    );
    assert.equal(respondReplay.exitCode, 0, respondReplay.stderr || respondReplay.stdout);
    const replayVerify = parseLastJsonFromStdout(respondReplay.stdout) as {
      decision?: string;
    } | null;
    assert.ok(replayVerify);
    assert.equal(replayVerify.decision, "DENY");

    console.log("Test 2 (legacy): /v1/issue -> /v1/requirements -> /v1/verify adapter");
    let requirements = await requestJson<{
      challenge: { nonce: string; audience: string };
      requirements: Array<{
        vct: string;
        disclosures?: string[];
        predicates?: Array<{ path: string; op: string; value?: unknown }>;
      }>;
      request_jwt?: string;
    }>(policyRequirementsUrl("marketplace.list_item"));
    if (GATEWAY_MODE || SOCIAL_MODE) {
      assert.ok(
        requirements.request_jwt,
        "strict posture: request_jwt must be present from gateway"
      );
      assert.ok(
        requirements.challenge.audience.startsWith("origin:"),
        "strict posture: audience must be origin-scoped"
      );
    }
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

    console.log("Test 2x: DID ↔ cnf key binding (DENY on wrong holder key)");
    const mismatchKeys = await generateEd25519KeyPair(`holder-mismatch-${testRunId}`);
    const didKeyReq = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(policyRequirementsUrl("marketplace.list_item"));
    const didKeyMismatchPresentation = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: didKeyReq.challenge.nonce,
      audience: didKeyReq.challenge.audience,
      holderJwk: mismatchKeys.publicJwk,
      holderKey: mismatchKeys.cryptoKey
    });
    const didKeyMismatch = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: didKeyMismatchPresentation,
        nonce: didKeyReq.challenge.nonce,
        audience: didKeyReq.challenge.audience
      }
    );
    assert.equal(didKeyMismatch.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(didKeyMismatch.reasons?.includes("did_key_not_authorized"));
    }
    const didKeyReqOk = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(policyRequirementsUrl("marketplace.list_item"));
    const didKeyOkPresentation = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: didKeyReqOk.challenge.nonce,
      audience: didKeyReqOk.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const didKeyOk = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: didKeyOkPresentation,
        nonce: didKeyReqOk.challenge.nonce,
        audience: didKeyReqOk.challenge.audience
      }
    );
    assert.equal(didKeyOk.decision, "ALLOW");

    console.log("Test 2y: Origin-scoped audience prevents replay across origins");
    const reqOriginA = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(policyRequirementsUrl("marketplace.list_item", { origin: verifierOrigin }));
    const reqOriginB = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(policyRequirementsUrl("marketplace.list_item", { origin: "https://evil.local" }));
    const originPresentation = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: reqOriginA.challenge.nonce,
      audience: reqOriginA.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const replayAcrossOrigin = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: originPresentation,
        nonce: reqOriginB.challenge.nonce,
        audience: reqOriginB.challenge.audience
      }
    );
    assert.equal(replayAcrossOrigin.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(replayAcrossOrigin.reasons?.includes("aud_mismatch"));
    }

    console.log(
      "Test 2z-strict: Strict posture assertions (origin audience, request JWT, unsigned fails)"
    );
    const directPolicyUrl = `${POLICY_SERVICE_BASE_URL}/v1/requirements?action=${encodeURIComponent(
      "marketplace.list_item"
    )}`;
    const actionOnlyReq = await requestJson<{
      challenge: { nonce: string; audience: string };
      requirements: Array<{ vct: string; disclosures?: string[] }>;
      request_jwt?: string;
    }>(directPolicyUrl);
    assert.ok(
      !actionOnlyReq.challenge.audience.startsWith("origin:"),
      "direct policy without verifier_origin must yield action-only audience"
    );
    assert.ok(
      !actionOnlyReq.request_jwt,
      "strict posture: direct policy response must not include request_jwt (gateway adds it)"
    );
    const actionOnlyPresentation = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: actionOnlyReq.challenge.nonce,
      audience: actionOnlyReq.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const actionOnlyVerify = await postJson<VerifyResponse>(
      `${VERIFIER_SERVICE_BASE_URL}/v1/verify?action=marketplace.list_item`,
      {
        presentation: actionOnlyPresentation,
        nonce: actionOnlyReq.challenge.nonce,
        audience: actionOnlyReq.challenge.audience
      }
    );
    assert.equal(actionOnlyVerify.decision, "DENY");
    assert.ok(
      actionOnlyVerify.reasons?.includes("audience_origin_required"),
      "strict posture: action-only audience must be denied with audience_origin_required"
    );
    // Wallet strict mode: reject unsigned request objects (missing request_jwt).
    // The verifier-service can serve an unsigned OID4VP request object directly; the gateway is responsible
    // for attaching request_jwt on the consumer surface.
    const unsignedReq = await requestJson(
      `${VERIFIER_SERVICE_BASE_URL}/oid4vp/request?action=${encodeURIComponent(
        "marketplace.list_item"
      )}&verifier_origin=${encodeURIComponent(verifierOrigin)}`
    );
    const unsignedReqPath = await writeJsonArgFile(
      walletDir,
      "oid4vp-request-unsigned",
      unsignedReq
    );
    const respondUnsigned = await runWalletCli(
      ["vp:respond", "--request", `@${unsignedReqPath}`],
      walletEnvVp
    );
    assert.notEqual(respondUnsigned.exitCode, 0);
    assert.ok(
      respondUnsigned.stderr.includes("request_jwt_missing_strict_mode") ||
        (respondUnsigned.stdout + respondUnsigned.stderr).includes(
          "request_jwt_missing_strict_mode"
        ),
      "strict posture: wallet must reject unsigned request (no request_jwt)"
    );

    console.log("Test 2z: Challenge consumed on first verify attempt (even on DENY)");
    const consumeReq = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(policyRequirementsUrl("marketplace.list_item"));
    const consumeOkPresentation = await buildPresentation({
      sdJwt: issueResponse.credential,
      disclose: disclosureList,
      nonce: consumeReq.challenge.nonce,
      audience: consumeReq.challenge.audience,
      holderJwk: holderKeys.publicJwk,
      holderKey: holderKeys.cryptoKey
    });
    const consumeBadPresentation = consumeOkPresentation.replace("~", "~~");
    const firstAttempt = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: consumeBadPresentation,
        nonce: consumeReq.challenge.nonce,
        audience: consumeReq.challenge.audience
      }
    );
    assert.equal(firstAttempt.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(firstAttempt.reasons?.includes("sd_hash_mismatch"));
    }
    const secondAttempt = await postJson<VerifyResponse>(
      `${verifyBaseUrl}/v1/verify?action=marketplace.list_item`,
      {
        presentation: consumeBadPresentation,
        nonce: consumeReq.challenge.nonce,
        audience: consumeReq.challenge.audience
      }
    );
    assert.equal(secondAttempt.decision, "DENY");
    if (INCLUDE_VERIFY_REASONS) {
      assert.ok(secondAttempt.reasons?.includes("challenge_consumed"));
    }

    console.log("Test 2a: Missing KB-JWT always DENY");
    const sdJwtPresentation = await presentSdJwtVc({
      sdJwt: issueResponse.credential,
      disclose: disclosureList
    });
    const missingKbRequirements = await requestJson<{
      challenge: { nonce: string; audience: string };
    }>(policyRequirementsUrl("marketplace.list_item"));
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
    }>(policyRequirementsUrl("marketplace.list_item"));
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
    }>(policyRequirementsUrl("marketplace.list_item"));
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
    let revokeSatisfied = false;
    while (Date.now() - revokeStartedAt < 180_000) {
      let requirementsAfterRevoke = await requestJson<{
        challenge: { nonce: string; audience: string };
        requirements: Array<{
          vct: string;
          disclosures?: string[];
          predicates?: Array<{ path: string; op: string; value?: unknown }>;
        }>;
      }>(policyRequirementsUrl("marketplace.list_item"));
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
        revokeSatisfied = true;
        break;
      }
      await sleep(5000);
    }
    if (!revokeSatisfied) {
      await emitAnchorDiagnostics(db, "revoke_verify_deny");
      if (SOCIAL_MODE) {
        await emitSocialTimeoutDiagnostics(db, "revoke_verify_deny");
      }
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
    }>(policyRequirementsUrl("dev.aura.signal"));
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
    const marketplaceRuleOutputVct = String(requirement.vct ?? "").trim();
    const marketplaceRules = await db("aura_rules")
      .where({
        domain: "marketplace",
        enabled: true,
        output_vct: marketplaceRuleOutputVct
      })
      .orderBy("updated_at", "desc");
    if (marketplaceRules.length !== 1) {
      await emitAnchorDiagnostics(db, "aura_rule_resolution_marketplace");
      if (SOCIAL_MODE) {
        await emitSocialTimeoutDiagnostics(db, "aura_rule_resolution_marketplace");
      }
      throw new Error(
        `Expected exactly one enabled marketplace aura rule for output_vct=${marketplaceRuleOutputVct}; found ${marketplaceRules.length}`
      );
    }
    const marketplaceRule = marketplaceRules[0] as {
      output_vct: string;
      rule_logic: unknown;
    };
    const marketplaceRuleLogic =
      typeof marketplaceRule.rule_logic === "string"
        ? (JSON.parse(marketplaceRule.rule_logic) as Record<string, unknown>)
        : ((marketplaceRule.rule_logic ?? {}) as Record<string, unknown>);
    const marketplaceSignalName = Array.isArray(marketplaceRuleLogic.signals)
      ? String(marketplaceRuleLogic.signals[0] ?? "marketplace.listing_success")
      : "marketplace.listing_success";
    const marketplaceOutputVct = String(marketplaceRule.output_vct ?? "").trim();
    assert.ok(marketplaceOutputVct.length > 0, "marketplace aura rule missing output_vct");

    // Deterministic CI stabilization: seed a diverse signal set that satisfies silver-tier minima.
    // Claim eligibility is computed from aura_signals, so this removes queue visibility races.
    const scoreCfg = (marketplaceRuleLogic.score ?? {}) as Record<string, unknown>;
    const diversityCfg = (marketplaceRuleLogic.diversity ?? {}) as Record<string, unknown>;
    const minSilverScoreRaw = scoreCfg.min_silver;
    const minSilverDiversityRaw = diversityCfg.min_for_silver;
    const minSilverScore =
      typeof minSilverScoreRaw === "number" &&
      Number.isFinite(minSilverScoreRaw) &&
      minSilverScoreRaw > 0
        ? Math.floor(minSilverScoreRaw)
        : 1;
    const minSilverDiversity =
      typeof minSilverDiversityRaw === "number" &&
      Number.isFinite(minSilverDiversityRaw) &&
      minSilverDiversityRaw > 0
        ? Math.floor(minSilverDiversityRaw)
        : 1;
    // Keep at least 4 counterparties so anti-collusion top2 ratio checks have room.
    const fallbackSignalCount = Math.max(minSilverScore, minSilverDiversity, 4);
    const fallbackSignalAt = new Date().toISOString();
    const fallbackSignals: Array<{ event_hash: string; counterparty_did_hash: string }> =
      Array.from({ length: fallbackSignalCount }, (_, idx) => {
        const counterpartyDidHash = pseudonymizer.didToHash(
          `did:example:counterparty:${idx}:${testRunId}`
        );
        return {
          event_hash: hashCanonicalJson({
            signal: marketplaceSignalName,
            domain: "marketplace",
            subjectDidHash: subjectHash,
            counterpartyDidHash,
            createdAt: fallbackSignalAt,
            nonce: `fallback-${idx}-${testRunId}`
          }),
          counterparty_did_hash: counterpartyDidHash
        };
      });
    for (const signalRow of fallbackSignals) {
      await db("aura_signals")
        .insert({
          subject_did_hash: subjectHash,
          domain: "marketplace",
          signal: marketplaceSignalName,
          weight: 1,
          counterparty_did_hash: signalRow.counterparty_did_hash,
          event_hash: signalRow.event_hash,
          created_at: fallbackSignalAt,
          processed_at: null
        })
        .onConflict("event_hash")
        .ignore();
    }
    await runAuraWorkerOnce();
    const auraClaimStartedAt = Date.now();
    const auraClaimTimeoutMs = 300_000;
    let auraClaim: { status: string; credential: string | null } | null = null;
    let lastAuraClaimError: string | null = null;
    let auraClaimAttempts = 0;
    while (Date.now() - auraClaimStartedAt < auraClaimTimeoutMs) {
      try {
        auraClaimAttempts += 1;
        auraClaim = await postJson<{
          status: string;
          credential: string | null;
        }>(
          `${ISSUER_SERVICE_BASE_URL}/v1/aura/claim`,
          { subjectDid: holderDid, output_vct: marketplaceOutputVct },
          { Authorization: `Bearer ${serviceTokenIssuer}` }
        );
        break;
      } catch (error) {
        const retryReason = getAuraClaimRetryReason(error);
        if (!retryReason) {
          throw error;
        }
        lastAuraClaimError = error instanceof Error ? error.message : String(error);
        // Keep retries under issuer claim limiter (10/minute).
        // For 429, wait well past the limiter window before retrying.
        const retryDelayMs = retryReason === "rate_limited" ? 70_000 : 8_000;
        if (retryReason !== "rate_limited") {
          await runAuraWorkerOnce();
        }
        await sleep(retryDelayMs);
      }
    }
    if (!auraClaim) {
      await emitAnchorDiagnostics(db, "aura_claim_not_ready");
      if (SOCIAL_MODE) {
        await emitSocialTimeoutDiagnostics(db, "aura_claim_not_ready");
      }
      throw new Error(
        `Timed out waiting for aura claim readiness after ${auraClaimTimeoutMs}ms attempts=${auraClaimAttempts} lastError=${lastAuraClaimError ?? "none"}`
      );
    }
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
    }>(policyRequirementsUrl("dev.aura.signal"));
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
    }>(policyRequirementsUrl("marketplace.list_item"));
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
      "anchor_outbox",
      ANCHOR_PHASE_TIMEOUT_MS,
      {
        onTimeout: async () => emitAnchorDiagnostics(db, "anchor_outbox_visible")
      }
    );
    const visiblePayloadHashes = anchorRows.map(
      (row: { payload_hash: string }) => row.payload_hash
    );
    const confirmedAnchorRows = await waitForDbRow(
      db,
      async () => {
        const rows = (await db("anchor_outbox as ao")
          .join("anchor_receipts as ar", "ar.payload_hash", "ao.payload_hash")
          .whereIn("ao.event_type", ["ISSUED", "VERIFY", "OBLIGATION_EXECUTED"])
          .andWhere("ao.created_at", ">=", runStartedAt)
          .andWhere("ao.status", "CONFIRMED")
          .whereNotNull("ar.topic_id")
          .whereNotNull("ar.sequence_number")
          .select("ao.payload_hash", "ao.created_at")
          .orderBy("ao.created_at", "desc")) as Array<{ payload_hash: string; created_at: string }>;
        return rows.length >= 3 ? rows : null;
      },
      "anchor_receipts",
      ANCHOR_PHASE_TIMEOUT_MS,
      {
        onTimeout: async () => emitAnchorDiagnostics(db, "anchor_receipts_confirmed")
      }
    );
    const payloadHashes = confirmedAnchorRows
      .slice(0, 3)
      .map((row: { payload_hash: string }) => row.payload_hash);
    if (payloadHashes.length < 3) {
      throw new Error(
        `anchor_receipts_insufficient confirmed=${confirmedAnchorRows.length} visible=${visiblePayloadHashes.length}`
      );
    }

    console.log("Test 6a: Mirror reconciliation verifies anchored message content");
    const receipts = (await db("anchor_receipts")
      .whereIn("payload_hash", payloadHashes)
      .orderBy("created_at", "desc")
      .select("payload_hash", "topic_id", "sequence_number")) as Array<{
      payload_hash: string;
      topic_id: string;
      sequence_number: string;
    }>;
    assert.ok(receipts.length >= 2, "expected at least 2 anchor receipts for reconciliation");
    const goodPayloadHash = receipts[0]?.payload_hash;
    const tamperPayloadHash = receipts[1]?.payload_hash;
    assert.ok(goodPayloadHash && tamperPayloadHash);
    if (tamperPayloadHash) {
      // Negative test: tamper DB expectation (do NOT touch ledger).
      // Mirror message still has the original auth fields, so reconciliation must detect mismatch.
      await db("anchor_outbox")
        .where({ payload_hash: tamperPayloadHash })
        .update({
          payload_meta: db.raw(
            "jsonb_set(payload_meta, '{anchor_auth_sig}', to_jsonb(?::text), true)",
            ["0".repeat(64)]
          ),
          updated_at: new Date().toISOString()
        });
    }

    const reconcile = await postJson<{
      attempted: number;
      counts: Record<string, number>;
      results: Array<{ payloadHash: string; status: string; reason?: string }>;
    }>(
      `${ISSUER_SERVICE_BASE_URL}/v1/admin/anchors/reconcile`,
      { payloadHashes: [goodPayloadHash, tamperPayloadHash], force: true },
      { Authorization: `Bearer ${serviceTokenIssuer}` }
    );
    const reconcileStartedAt = Date.now();
    // Mirror indexing lag (topic creation + messages) can be several minutes on Testnet.
    // Keep this separate from the "outbox confirmed" timeout so the suite is less flaky.
    const MIRROR_RECONCILE_TEST_TIMEOUT_MS = Math.max(ANCHOR_PHASE_TIMEOUT_MS, 480_000);
    let lastReconcile = reconcile;
    let delayMs = 1000;
    let reconcileAttempt = 1;
    let timedOut = false;
    while (Date.now() - reconcileStartedAt < MIRROR_RECONCILE_TEST_TIMEOUT_MS) {
      const goodResult = lastReconcile.results.find((r) => r.payloadHash === goodPayloadHash);
      const tamperResult = lastReconcile.results.find((r) => r.payloadHash === tamperPayloadHash);
      if (goodResult?.status === "VERIFIED" && tamperResult?.status === "MISMATCH") {
        break;
      }
      if (
        goodResult?.status &&
        goodResult.status !== "VERIFIED" &&
        goodResult.status !== "NOT_FOUND"
      ) {
        console.log(
          `[diag] mirror_reconcile_unexpected_good_status status=${goodResult.status} reason=${goodResult.reason ?? ""}`
        );
        break;
      }
      if (
        tamperResult?.status &&
        tamperResult.status !== "MISMATCH" &&
        tamperResult.status !== "NOT_FOUND"
      ) {
        console.log(
          `[diag] mirror_reconcile_unexpected_tamper_status status=${tamperResult.status} reason=${tamperResult.reason ?? ""}`
        );
        break;
      }
      // Mirror lag is normal. Retry with gentle backoff to avoid hammering public mirrors.
      await sleep(delayMs);
      reconcileAttempt += 1;
      delayMs = jitteredBackoffMs(reconcileAttempt, 1000, 10_000);
      lastReconcile = await postJson(
        `${ISSUER_SERVICE_BASE_URL}/v1/admin/anchors/reconcile`,
        { payloadHashes: [goodPayloadHash, tamperPayloadHash], force: true },
        { Authorization: `Bearer ${serviceTokenIssuer}` }
      );
    }
    if (Date.now() - reconcileStartedAt >= MIRROR_RECONCILE_TEST_TIMEOUT_MS) {
      timedOut = true;
    }
    assert.ok(lastReconcile.attempted >= 1);
    const goodResult = lastReconcile.results.find((r) => r.payloadHash === goodPayloadHash);
    const tamperResult = lastReconcile.results.find((r) => r.payloadHash === tamperPayloadHash);
    if (timedOut && (goodResult?.status !== "VERIFIED" || tamperResult?.status !== "MISMATCH")) {
      console.log(
        `[diag] mirror_reconcile_timeout last=${JSON.stringify({
          good: goodResult,
          tamper: tamperResult,
          counts: lastReconcile.counts
        })}`
      );
      await emitAnchorDiagnostics(db, "mirror_reconcile_timeout");
    }
    assert.ok(goodResult);
    assert.equal(goodResult?.status, "VERIFIED");
    assert.ok(tamperResult);
    assert.equal(tamperResult?.status, "MISMATCH");

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
    }>(policyRequirementsUrl("marketplace.list_item"));
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
    }>(policyRequirementsUrl("marketplace.list_item"));
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
    }>(policyRequirementsUrl("marketplace.list_item"));
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
      const acceptedStatusListFailureReasons = new Set([
        "status_list_unavailable",
        "status_list_fetch_failed",
        "status_list_missing",
        "status_list_invalid_signature",
        "status_list_url_invalid",
        "verification_failed"
      ]);
      const afterTtlReasons = afterTtlVerify.reasons ?? [];
      const hasAcceptedStatusListFailureReason = afterTtlReasons.some((reason) =>
        acceptedStatusListFailureReasons.has(reason)
      );
      if (!hasAcceptedStatusListFailureReason) {
        const statusListStatusRegex = /(?:status["=:]\s*|status=)(\d{3})/i;
        const parseStatusListFetchStatus = (serviceName: string) => {
          const rows = serviceLogTail.get(serviceName) ?? [];
          for (let index = rows.length - 1; index >= 0; index -= 1) {
            const line = rows[index];
            const hasStatusListHint =
              line.includes("status-lists") ||
              line.includes("status_list") ||
              line.includes("status list");
            if (!hasStatusListHint) {
              continue;
            }
            const match = line.match(statusListStatusRegex);
            if (match?.[1]) {
              return Number(match[1]);
            }
          }
          return null;
        };
        const verifierStatusListHttpStatus = parseStatusListFetchStatus("verifier-service");
        const issuerStatusListHttpStatus = parseStatusListFetchStatus("issuer-service");
        console.log(
          `[diag] status_list_ttl_fail_closed_mismatch decision=${afterTtlVerify.decision} reasons=${JSON.stringify(
            afterTtlVerify.reasons ?? null
          )} verifier_status_list_http_status=${String(
            verifierStatusListHttpStatus ?? "unknown"
          )} issuer_status_list_http_status=${String(issuerStatusListHttpStatus ?? "unknown")}`
        );
        emitServiceLogTail("verifier-service", 80);
        emitServiceLogTail("issuer-service", 80);
        assert.fail(
          `expected one of ${JSON.stringify(Array.from(acceptedStatusListFailureReasons))}, got ${JSON.stringify(afterTtlVerify.reasons ?? null)}`
        );
      }
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

    if (SOCIAL_MODE) {
      if (!services.gateway) {
        throw new Error("social_mode_requires_gateway");
      }
      console.log("Test 8: SOCIAL vertical policy-gated flow");
      const socialFlowStart = Date.now();
      const buildSocialClaims = (vct: string) => {
        const asOf = new Date().toISOString();
        if (vct === "cuncta.social.can_comment") {
          return { can_comment: true, tier: "bronze", domain: "social", as_of: asOf };
        }
        if (vct === "cuncta.social.trusted_creator") {
          return { trusted_creator: true, tier: "silver", domain: "social", as_of: asOf };
        }
        if (vct === "cuncta.social.space.member") {
          return {
            member: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.social.space.poster") {
          return {
            poster: true,
            tier: "silver",
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.social.space.moderator") {
          return {
            moderator: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.social.space.steward") {
          return {
            steward: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.sync.scroll_host") {
          return {
            scroll_host: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.sync.listen_host") {
          return {
            listen_host: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.sync.session_participant") {
          return {
            participant: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        if (vct === "cuncta.presence.mode_access") {
          return {
            mode_access: true,
            domain: "space:placeholder",
            space_id: "placeholder",
            as_of: asOf
          };
        }
        return { account_active: true, domain: "social", as_of: asOf };
      };
      const runSocialPhase = async <T>(phase: string, waitedOn: string, fn: () => Promise<T>) => {
        const phaseStart = Date.now();
        console.log(
          `[social.phase.start] phase=${phase} total_elapsed_ms=${Date.now() - socialFlowStart} waited_on=${waitedOn}`
        );
        const previousStep = currentIntegrationStep;
        currentIntegrationStep = `social:${phase}`;
        try {
          const result = await fn();
          console.log(
            `[social.phase.ok] phase=${phase} elapsed_ms=${Date.now() - phaseStart} total_elapsed_ms=${Date.now() - socialFlowStart} waited_on=${waitedOn}`
          );
          return result;
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          console.error(
            `[social.phase.fail] phase=${phase} elapsed_ms=${Date.now() - phaseStart} total_elapsed_ms=${Date.now() - socialFlowStart} error=${detail}`
          );
          if (detail.toLowerCase().includes("timed out")) {
            await emitSocialTimeoutDiagnostics(db, phase);
          }
          throw error;
        } finally {
          currentIntegrationStep = previousStep;
        }
      };
      const waitForSocialDbRow = async <T>(
        phase: string,
        label: string,
        query: () => Promise<T | null | undefined>,
        timeoutMs = 180_000,
        pollMs = 2000
      ) =>
        waitForDbRow(db, query, `social:${label}`, timeoutMs, {
          pollMs,
          onTimeout: async () => {
            await emitSocialTimeoutDiagnostics(db, phase);
          }
        });

      const hashPrefix = (value: string | null | undefined) =>
        value && value.length > 0 ? value.slice(0, 12) : "none";
      const parseAuraTier = (raw: unknown): "bronze" | "silver" | "gold" => {
        const fallback = "bronze" as const;
        if (!raw || typeof raw !== "object") {
          if (typeof raw === "string") {
            try {
              const parsed = JSON.parse(raw) as unknown;
              return parseAuraTier(parsed);
            } catch {
              return fallback;
            }
          }
          return fallback;
        }
        const tierValue = String((raw as Record<string, unknown>).tier ?? "bronze").toLowerCase();
        if (tierValue === "gold" || tierValue === "silver" || tierValue === "bronze") {
          return tierValue;
        }
        return fallback;
      };
      const getAuraTierForDomain = async (subjectDidHash: string, domain: string) => {
        const row = (await db("aura_state")
          .where({ subject_did_hash: subjectDidHash, domain })
          .select("state")
          .first()) as { state?: unknown } | undefined;
        return parseAuraTier(row?.state);
      };
      const hasTrustedCreatorCredential = async (subjectDidHash: string) => {
        const row = await db("issuance_events")
          .where({ subject_did_hash: subjectDidHash, vct: "cuncta.social.trusted_creator" })
          .first();
        return Boolean(row);
      };
      const logFlowFeedSummary = async (input: {
        trust: "trusted_creator" | "verified_only" | "space_members";
        spaceId?: string;
        viewerSubjectHash: string;
        targetAuthorHash: string;
        posts: Array<{ post_id: string; trust_stamps?: string[] }>;
      }) => {
        console.log(
          `[diag] flow_feed_request trust=${input.trust} space_id=${input.spaceId ?? "none"} viewer_hash_prefix=${hashPrefix(input.viewerSubjectHash)} author_hash_prefix=${hashPrefix(input.targetAuthorHash)}`
        );
        if (input.posts.length === 0) {
          console.log("[diag] flow_feed_response empty feed");
          return;
        }
        const postIds = input.posts.map((entry) => entry.post_id);
        const postRows = (await db("social_posts")
          .whereIn("post_id", postIds)
          .select("post_id", "author_subject_did_hash")) as Array<{
          post_id: string;
          author_subject_did_hash: string;
        }>;
        const postById = new Map(postRows.map((row) => [String(row.post_id), row]));
        const authorHashes = Array.from(
          new Set(postRows.map((row) => String(row.author_subject_did_hash)))
        );
        const socialAuraRows = (await db("aura_state")
          .whereIn("subject_did_hash", authorHashes)
          .andWhere({ domain: "social" })
          .select("subject_did_hash", "state")) as Array<{
          subject_did_hash: string;
          state: unknown;
        }>;
        const socialTierByAuthor = new Map<string, "bronze" | "silver" | "gold">(
          socialAuraRows.map((row) => [row.subject_did_hash, parseAuraTier(row.state)])
        );
        const trustedRows = (await db("issuance_events")
          .whereIn("subject_did_hash", authorHashes)
          .andWhere({ vct: "cuncta.social.trusted_creator" })
          .select("subject_did_hash")
          .groupBy("subject_did_hash")) as Array<{ subject_did_hash: string }>;
        const trustedSet = new Set(trustedRows.map((row) => row.subject_did_hash));
        console.log(
          `[diag] flow_feed_response count=${input.posts.length} post_ids=${JSON.stringify(postIds)}`
        );
        for (const [index, post] of input.posts.entries()) {
          const row = postById.get(post.post_id);
          const authorHash = row?.author_subject_did_hash ?? "";
          const socialTier = socialTierByAuthor.get(authorHash) ?? "bronze";
          const trustStampSummary = {
            tier: socialTier,
            capability:
              socialTier === "gold" || socialTier === "silver" || trustedSet.has(authorHash)
                ? "trusted_creator"
                : "can_post",
            domain: "social"
          };
          console.log(
            `[diag] flow_feed_post[${index}] post_id=${post.post_id} author_hash_prefix=${hashPrefix(authorHash)} trust_stamps=${JSON.stringify(post.trust_stamps ?? [])} trust_stamp_summary=${JSON.stringify(trustStampSummary)}`
          );
        }
      };
      const logTrustedLensAuthorInputs = async (input: {
        viewerSubjectHash: string;
        targetAuthorHash: string;
        spaceId: string;
      }) => {
        const socialTier = await getAuraTierForDomain(input.targetAuthorHash, "social");
        const spaceTier = await getAuraTierForDomain(
          input.targetAuthorHash,
          `space:${input.spaceId}`
        );
        const trustedCreatorCredential = await hasTrustedCreatorCredential(input.targetAuthorHash);
        const viewerMembership = await db("social_space_memberships")
          .where({
            subject_did_hash: input.viewerSubjectHash,
            space_id: input.spaceId,
            status: "ACTIVE"
          })
          .first();
        const sharedMembership = await db("social_space_memberships as viewer")
          .join("social_space_memberships as author", "viewer.space_id", "author.space_id")
          .where("viewer.subject_did_hash", input.viewerSubjectHash)
          .andWhere("viewer.status", "ACTIVE")
          .andWhere("author.subject_did_hash", input.targetAuthorHash)
          .andWhere("author.status", "ACTIVE")
          .select("viewer.space_id")
          .first();
        const moderationRestriction = await db("social_space_member_restrictions")
          .where({ subject_did_hash: input.targetAuthorHash, space_id: input.spaceId })
          .first();
        console.log(
          `[diag] trusted_lens_inputs social_tier=${socialTier} space_tier=${spaceTier} trusted_creator_credential=${trustedCreatorCredential} viewer_space_member=${Boolean(viewerMembership)} viewer_shared_space_with_author=${Boolean(sharedMembership)} author_moderation_restricted=${Boolean(moderationRestriction)} viewer_hash_prefix=${hashPrefix(input.viewerSubjectHash)} author_hash_prefix=${hashPrefix(input.targetAuthorHash)}`
        );
      };
      const getPrivacyFlags = async (subjectDidHash: string) => {
        const [restricted, tombstoned] = await Promise.all([
          db("privacy_restrictions").where({ did_hash: subjectDidHash }).first(),
          db("privacy_tombstones").where({ did_hash: subjectDidHash }).first()
        ]);
        return {
          restricted: Boolean(restricted),
          tombstoned: Boolean(tombstoned)
        };
      };
      const logSpaceLensInputs = async (input: {
        viewerSubjectHash: string;
        targetAuthorHash: string;
        spaceId: string;
      }) => {
        const [
          viewerMembershipRows,
          authorMembershipRows,
          sharedRows,
          viewerPrivacy,
          authorPrivacy
        ] = await Promise.all([
          db("social_space_memberships")
            .where({
              subject_did_hash: input.viewerSubjectHash,
              space_id: input.spaceId,
              status: "ACTIVE"
            })
            .count<{ count: string }>("space_id as count")
            .first(),
          db("social_space_memberships")
            .where({
              subject_did_hash: input.targetAuthorHash,
              space_id: input.spaceId,
              status: "ACTIVE"
            })
            .count<{ count: string }>("space_id as count")
            .first(),
          db("social_space_memberships as viewer")
            .join("social_space_memberships as author", "viewer.space_id", "author.space_id")
            .where("viewer.subject_did_hash", input.viewerSubjectHash)
            .andWhere("viewer.status", "ACTIVE")
            .andWhere("author.subject_did_hash", input.targetAuthorHash)
            .andWhere("author.status", "ACTIVE")
            .andWhere("viewer.space_id", input.spaceId)
            .count<{ count: string }>("viewer.space_id as count")
            .first(),
          getPrivacyFlags(input.viewerSubjectHash),
          getPrivacyFlags(input.targetAuthorHash)
        ]);
        const [viewerModeration, authorModeration] = await Promise.all([
          db("social_space_member_restrictions")
            .where({
              subject_did_hash: input.viewerSubjectHash,
              space_id: input.spaceId
            })
            .first(),
          db("social_space_member_restrictions")
            .where({
              subject_did_hash: input.targetAuthorHash,
              space_id: input.spaceId
            })
            .first()
        ]);
        console.log(
          `[diag] space_lens_inputs space_id=${input.spaceId} viewer_hash_prefix=${hashPrefix(input.viewerSubjectHash)} author_hash_prefix=${hashPrefix(input.targetAuthorHash)} viewer_space_member=${Number(viewerMembershipRows?.count ?? 0) > 0} author_space_member=${Number(authorMembershipRows?.count ?? 0) > 0} viewer_shared_space_with_author=${Number(sharedRows?.count ?? 0) > 0} viewer_membership_rows=${Number(viewerMembershipRows?.count ?? 0)} author_membership_rows=${Number(authorMembershipRows?.count ?? 0)} viewer_privacy_restricted=${viewerPrivacy.restricted} viewer_privacy_tombstoned=${viewerPrivacy.tombstoned} author_privacy_restricted=${authorPrivacy.restricted} author_privacy_tombstoned=${authorPrivacy.tombstoned} viewer_moderation_restricted=${Boolean(viewerModeration)} author_moderation_restricted=${Boolean(authorModeration)}`
        );
      };
      const logSpaceFlowSummary = async (input: {
        endpoint: string;
        trust: "trusted_creator" | "verified_only" | "space_members" | "none";
        spaceId: string;
        viewerSubjectHash: string;
        targetAuthorHash: string;
        posts: Array<{ space_post_id: string; trust_stamps?: string[] }>;
      }) => {
        console.log(
          `[diag] space_flow_request endpoint=${input.endpoint} trust=${input.trust} space_id=${input.spaceId} viewer_hash_prefix=${hashPrefix(input.viewerSubjectHash)} author_hash_prefix=${hashPrefix(input.targetAuthorHash)}`
        );
        if (input.posts.length === 0) {
          console.log("[diag] space_flow_response empty feed");
          return;
        }
        const spacePostIds = input.posts.map((entry) => entry.space_post_id);
        const postRows = (await db("social_space_posts")
          .whereIn("space_post_id", spacePostIds)
          .select("space_post_id", "author_subject_did_hash")) as Array<{
          space_post_id: string;
          author_subject_did_hash: string;
        }>;
        const postById = new Map(postRows.map((row) => [String(row.space_post_id), row]));
        const authorHashes = Array.from(
          new Set(postRows.map((row) => String(row.author_subject_did_hash)))
        );
        const socialAuraRows = (await db("aura_state")
          .whereIn("subject_did_hash", authorHashes)
          .andWhere({ domain: "social" })
          .select("subject_did_hash", "state")) as Array<{
          subject_did_hash: string;
          state: unknown;
        }>;
        const spaceAuraRows = (await db("aura_state")
          .whereIn("subject_did_hash", authorHashes)
          .andWhere({ domain: `space:${input.spaceId}` })
          .select("subject_did_hash", "state")) as Array<{
          subject_did_hash: string;
          state: unknown;
        }>;
        const socialTierByAuthor = new Map<string, "bronze" | "silver" | "gold">(
          socialAuraRows.map((row) => [row.subject_did_hash, parseAuraTier(row.state)])
        );
        const spaceTierByAuthor = new Map<string, "bronze" | "silver" | "gold">(
          spaceAuraRows.map((row) => [row.subject_did_hash, parseAuraTier(row.state)])
        );
        const trustedRows = (await db("issuance_events")
          .whereIn("subject_did_hash", authorHashes)
          .andWhere({ vct: "cuncta.social.trusted_creator" })
          .select("subject_did_hash")
          .groupBy("subject_did_hash")) as Array<{ subject_did_hash: string }>;
        const trustedSet = new Set(trustedRows.map((row) => row.subject_did_hash));
        console.log(
          `[diag] space_flow_response count=${input.posts.length} post_ids=${JSON.stringify(spacePostIds)}`
        );
        for (const [index, post] of input.posts.entries()) {
          const row = postById.get(post.space_post_id);
          const authorHash = row?.author_subject_did_hash ?? "";
          const socialTier = socialTierByAuthor.get(authorHash) ?? "bronze";
          const spaceTier = spaceTierByAuthor.get(authorHash) ?? "bronze";
          const effectiveTier =
            socialTier === "gold" || spaceTier === "gold"
              ? "gold"
              : socialTier === "silver" || spaceTier === "silver"
                ? "silver"
                : "bronze";
          const trustStampSummary = {
            tier: effectiveTier,
            capability:
              effectiveTier === "gold" || effectiveTier === "silver" || trustedSet.has(authorHash)
                ? "trusted_creator"
                : "can_post",
            domain: `space:${input.spaceId}`
          };
          console.log(
            `[diag] space_flow_post[${index}] space_post_id=${post.space_post_id} author_hash_prefix=${hashPrefix(authorHash)} trust_stamps=${JSON.stringify(post.trust_stamps ?? [])} trust_stamp_summary=${JSON.stringify(trustStampSummary)}`
          );
        }
      };

      await runSocialPhase(
        "space default pack pinning",
        "DB social_space_policy_packs pinned hashes non-null",
        async () => {
          const pack = await db("social_space_policy_packs")
            .where({ policy_pack_id: "space.default.v1" })
            .first();
          assert.ok(pack, "expected default space policy pack");
          assert.ok(
            pack.pinned_policy_hash_join &&
              pack.pinned_policy_hash_post &&
              pack.pinned_policy_hash_moderate,
            "expected pinned default pack hashes to be non-null"
          );
        }
      );

      const socialHolderKeys = await runSocialPhase(
        "did onboarding",
        "did resolution for social holder",
        async () => generateEd25519KeyPair(`holder-social-${testRunId}`)
      );
      const socialHolderDid = await runSocialPhase(
        "did onboarding",
        "createDid + waitForDidResolution",
        async () =>
          createDid({
            publicKey: socialHolderKeys.publicKey,
            privateKey: socialHolderKeys.privateKey,
            token: serviceTokenDid
          })
      );
      const socialSubjectHash = createHmacSha256Pseudonymizer({
        pepper: PSEUDONYMIZER_PEPPER
      }).didToHash(socialHolderDid);
      const createSocialActor = async (suffix: string) => {
        const keys = await generateEd25519KeyPair(`holder-social-${suffix}-${testRunId}`);
        const did = await createDid({
          publicKey: keys.publicKey,
          privateKey: keys.privateKey,
          token: serviceTokenDid
        });
        const requirements = await ensureRequirements(
          "social.profile.create",
          await requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.profile.create"))
        );
        const baseCredential = await issueCredentialFor({
          subjectDid: did,
          vct: requirements.requirements[0].vct,
          claims: {
            account_active: true,
            domain: "social",
            as_of: new Date().toISOString()
          }
        });
        const presentation = await buildPresentation({
          sdJwt: baseCredential.credential,
          disclose: buildDisclosureList(requirements.requirements[0]),
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: keys.publicJwk,
          holderKey: keys.cryptoKey
        });
        const profile = await postJson<{ decision: string; profileId: string }>(
          `${APP_GATEWAY_BASE_URL}/v1/social/profile/create`,
          {
            subjectDid: did,
            handle: `social-${suffix}-${testRunId.slice(0, 6)}`,
            presentation,
            nonce: requirements.challenge.nonce,
            audience: requirements.challenge.audience
          }
        );
        assert.equal(profile.decision, "ALLOW");
        return { did, keys, baseCredential };
      };

      const socialProfileRequirements = await runSocialPhase(
        "base social credential issuance",
        "GET /v1/social/requirements social.profile.create",
        async () => {
          const requirements = await requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.profile.create"));
          return ensureRequirements("social.profile.create", requirements);
        }
      );
      const socialProfileReq = socialProfileRequirements.requirements[0];
      assert.ok(socialProfileReq, "expected social profile requirement");

      const socialBaseCredential = await runSocialPhase(
        "base social credential issuance",
        "issuer /v1/issue social account credential",
        async () =>
          issueCredentialFor({
            subjectDid: socialHolderDid,
            vct: socialProfileReq.vct,
            claims: {
              account_active: true,
              domain: "social",
              as_of: new Date().toISOString()
            }
          })
      );

      const socialProfilePresentation = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(socialProfileReq),
        nonce: socialProfileRequirements.challenge.nonce,
        audience: socialProfileRequirements.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const profileCreate = await runSocialPhase(
        "profile create",
        "POST /v1/social/profile/create decision=ALLOW",
        async () =>
          postJson<{ decision: string; profileId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/profile/create`,
            {
              subjectDid: socialHolderDid,
              handle: `social-${testRunId.slice(0, 8)}`,
              displayName: "Social Holder",
              presentation: socialProfilePresentation,
              nonce: socialProfileRequirements.challenge.nonce,
              audience: socialProfileRequirements.challenge.audience
            }
          )
      );
      assert.equal(profileCreate.decision, "ALLOW");
      assert.ok(profileCreate.profileId);

      const socialPostRequirements = await runSocialPhase(
        "post create",
        "GET /v1/social/requirements social.post.create",
        async () => {
          const requirements = await requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.post.create"));
          return ensureRequirements("social.post.create", requirements);
        }
      );
      const socialPostReq = socialPostRequirements.requirements[0];
      assert.ok(socialPostReq, "expected social post requirement");
      const socialPostPresentation = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(socialPostReq),
        nonce: socialPostRequirements.challenge.nonce,
        audience: socialPostRequirements.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const postAllowed = await runSocialPhase(
        "post create",
        "POST /v1/social/post decision=ALLOW",
        async () =>
          postJson<{ decision: string; postId: string }>(`${APP_GATEWAY_BASE_URL}/v1/social/post`, {
            subjectDid: socialHolderDid,
            content: "CUNCTA Social MVP post on Hedera Testnet.",
            visibility: "public",
            presentation: socialPostPresentation,
            nonce: socialPostRequirements.challenge.nonce,
            audience: socialPostRequirements.challenge.audience
          })
      );
      assert.equal(postAllowed.decision, "ALLOW");
      assert.ok(postAllowed.postId);

      const socialReplyRequirements = await runSocialPhase(
        "reply create",
        "GET /v1/social/requirements social.reply.create",
        async () =>
          requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.reply.create"))
      );
      const socialReplyCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: socialReplyRequirements.requirements[0].vct,
        claims: buildSocialClaims(socialReplyRequirements.requirements[0].vct)
      });
      const socialReplyPresentation = await buildPresentation({
        sdJwt: socialReplyCredential.credential,
        disclose: buildDisclosureList(socialReplyRequirements.requirements[0]),
        nonce: socialReplyRequirements.challenge.nonce,
        audience: socialReplyRequirements.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      await runSocialPhase("reply create", "POST /v1/social/reply decision=ALLOW", async () =>
        postJson<{ decision: string; replyId: string }>(`${APP_GATEWAY_BASE_URL}/v1/social/reply`, {
          subjectDid: socialHolderDid,
          postId: postAllowed.postId,
          content: "First reply on social MVP.",
          presentation: socialReplyPresentation,
          nonce: socialReplyRequirements.challenge.nonce,
          audience: socialReplyRequirements.challenge.audience
        })
      );

      const socialFollowRequirements = await runSocialPhase(
        "follow create",
        "GET /v1/social/requirements social.follow.create",
        async () =>
          requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.follow.create"))
      );
      const socialFollowPresentation = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(socialFollowRequirements.requirements[0]),
        nonce: socialFollowRequirements.challenge.nonce,
        audience: socialFollowRequirements.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      await runSocialPhase("follow create", "POST /v1/social/follow decision=ALLOW", async () =>
        postJson<{ decision: string }>(`${APP_GATEWAY_BASE_URL}/v1/social/follow`, {
          subjectDid: socialHolderDid,
          followeeDid: holderDid,
          presentation: socialFollowPresentation,
          nonce: socialFollowRequirements.challenge.nonce,
          audience: socialFollowRequirements.challenge.audience
        })
      );

      await runSocialPhase("report create", "POST /v1/social/report decision=ALLOW", async () => {
        const requirements = await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("social.report.create"));
        const reportPresentation = await buildPresentation({
          sdJwt: socialBaseCredential.credential,
          disclose: buildDisclosureList(requirements.requirements[0]),
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: socialHolderKeys.publicJwk,
          holderKey: socialHolderKeys.cryptoKey
        });
        const result = await postJson<{ decision: string; reportId: string }>(
          `${APP_GATEWAY_BASE_URL}/v1/social/report`,
          {
            subjectDid: socialHolderDid,
            targetPostId: postAllowed.postId,
            reasonCode: "abuse",
            presentation: reportPresentation,
            nonce: requirements.challenge.nonce,
            audience: requirements.challenge.audience
          }
        );
        assert.equal(result.decision, "ALLOW");
        return result;
      });

      const spaceCreateRequirements = await runSocialPhase(
        "space create",
        "GET /v1/social/requirements social.space.create",
        async () =>
          requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.space.create"))
      );
      const spaceCreatePresentation = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(spaceCreateRequirements.requirements[0]),
        nonce: spaceCreateRequirements.challenge.nonce,
        audience: spaceCreateRequirements.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const createdSpace = await runSocialPhase(
        "space create",
        "POST /v1/social/space/create decision=ALLOW",
        async () =>
          postJson<{ decision: string; spaceId: string; policyPackId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/create`,
            {
              subjectDid: socialHolderDid,
              slug: `space-${testRunId.slice(0, 8)}`,
              displayName: "CUNCTA Space",
              description: "Flagship trust-native space",
              policyPackId: "space.default.v1",
              presentation: spaceCreatePresentation,
              nonce: spaceCreateRequirements.challenge.nonce,
              audience: spaceCreateRequirements.challenge.audience
            }
          )
      );
      assert.equal(createdSpace.decision, "ALLOW");
      assert.ok(createdSpace.spaceId);
      await runSocialPhase(
        "spaces directory",
        "GET /v1/social/spaces contains created space",
        async () => {
          const spaces = await requestJson<{
            spaces: Array<{ space_id: string; posting_requirement_summary?: string }>;
          }>(`${APP_GATEWAY_BASE_URL}/v1/social/spaces?limit=20`);
          assert.ok(spaces.spaces.some((entry) => entry.space_id === createdSpace.spaceId));
        }
      );
      await runSocialPhase(
        "space rules preview",
        "GET /v1/social/spaces/:spaceId/rules returns requirement summaries",
        async () => {
          const rules = await requestJson<{
            join_requirements?: Array<{ vct: string; label?: string }>;
            post_requirements?: Array<{ vct: string; label?: string }>;
            moderation_requirements?: Array<{ vct: string; label?: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/rules`
          );
          assert.ok((rules.join_requirements?.length ?? 0) > 0);
          assert.ok((rules.post_requirements?.length ?? 0) > 0);
          assert.ok((rules.moderation_requirements?.length ?? 0) > 0);
        }
      );
      await runSocialPhase(
        "space governance transparency",
        "GET /v1/social/spaces/:spaceId/governance returns pack, versions, and floor",
        async () => {
          const governance = await requestJson<{
            policy_pack?: { policy_pack_id?: string };
            policy_versions?: { post?: { version?: number | null } };
            trust_floor?: { post?: string };
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/governance`
          );
          assert.equal(governance.policy_pack?.policy_pack_id, "space.default.v1");
          assert.ok((governance.policy_versions?.post?.version ?? 0) >= 1);
          assert.ok(
            ["bronze", "silver", "gold"].includes(String(governance.trust_floor?.post ?? "bronze"))
          );
        }
      );
      const secondSpaceRequirements = await runSocialPhase(
        "space create (secondary)",
        "GET /v1/social/requirements social.space.create",
        async () =>
          requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.space.create"))
      );
      const secondSpacePresentation = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(secondSpaceRequirements.requirements[0]),
        nonce: secondSpaceRequirements.challenge.nonce,
        audience: secondSpaceRequirements.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const createdSpaceB = await runSocialPhase(
        "space create (secondary)",
        "POST /v1/social/space/create decision=ALLOW",
        async () =>
          postJson<{ decision: string; spaceId: string; policyPackId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/create`,
            {
              subjectDid: socialHolderDid,
              slug: `space-b-${testRunId.slice(0, 8)}`,
              displayName: "CUNCTA Space B",
              description: "Cross-space binding test target",
              policyPackId: "space.default.v1",
              presentation: secondSpacePresentation,
              nonce: secondSpaceRequirements.challenge.nonce,
              audience: secondSpaceRequirements.challenge.audience
            }
          )
      );
      assert.equal(createdSpaceB.decision, "ALLOW");
      assert.ok(createdSpaceB.spaceId);

      const issueSpaceCredential = async (actionId: string, claims: Record<string, unknown>) => {
        const requirementsUrl = new URL("/v1/social/requirements", APP_GATEWAY_BASE_URL);
        requirementsUrl.searchParams.set("action", actionId);
        requirementsUrl.searchParams.set("verifier_origin", gatewayOrigin);
        if (actionId.startsWith("social.space.") && typeof claims.space_id === "string") {
          requirementsUrl.searchParams.set("space_id", claims.space_id);
        }
        const requirements = await requestJson<{
          challenge: { nonce: string; audience: string };
          context?: { space_id?: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(requirementsUrl.toString());
        const requirement = requirements.requirements[0];
        assert.ok(requirement, `expected requirement for ${actionId}`);
        const credential = await issueCredentialFor({
          subjectDid: socialHolderDid,
          vct: requirement.vct,
          claims
        });
        const presentation = await buildPresentation({
          sdJwt: credential.credential,
          disclose: buildDisclosureList(requirement),
          nonce: requirements.challenge.nonce,
          audience: requirements.challenge.audience,
          holderJwk: socialHolderKeys.publicJwk,
          holderKey: socialHolderKeys.cryptoKey
        });
        return { requirements, presentation };
      };

      const spaceDomain = `space:${createdSpace.spaceId}`;
      const joinCredential = await issueSpaceCredential("social.space.join", {
        member: true,
        domain: spaceDomain,
        space_id: createdSpace.spaceId,
        as_of: new Date().toISOString()
      });
      await runSocialPhase("space join", "POST /v1/social/space/join decision=ALLOW", async () => {
        const result = await postJson<{ decision: string }>(
          `${APP_GATEWAY_BASE_URL}/v1/social/space/join`,
          {
            subjectDid: socialHolderDid,
            spaceId: createdSpace.spaceId,
            presentation: joinCredential.presentation,
            nonce: joinCredential.requirements.challenge.nonce,
            audience: joinCredential.requirements.challenge.audience
          }
        );
        assert.equal(result.decision, "ALLOW");
      });
      const joinCredentialB = await issueSpaceCredential("social.space.join", {
        member: true,
        domain: `space:${createdSpaceB.spaceId}`,
        space_id: createdSpaceB.spaceId,
        as_of: new Date().toISOString()
      });
      await runSocialPhase(
        "space join (secondary)",
        "POST /v1/social/space/join decision=ALLOW",
        async () => {
          const result = await postJson<{ decision: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/join`,
            {
              subjectDid: socialHolderDid,
              spaceId: createdSpaceB.spaceId,
              presentation: joinCredentialB.presentation,
              nonce: joinCredentialB.requirements.challenge.nonce,
              audience: joinCredentialB.requirements.challenge.audience
            }
          );
          assert.equal(result.decision, "ALLOW");
        }
      );
      const trustedActor = await runSocialPhase(
        "flow actor setup",
        "create second user with social profile",
        async () => createSocialActor("trusted")
      );
      const trustedPostRequirements = await ensureRequirements(
        "social.post.create",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("social.post.create"))
      );
      const trustedPostPresentation = await buildPresentation({
        sdJwt: trustedActor.baseCredential.credential,
        disclose: buildDisclosureList(trustedPostRequirements.requirements[0]),
        nonce: trustedPostRequirements.challenge.nonce,
        audience: trustedPostRequirements.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      const trustedPost = await runSocialPhase(
        "flow actor post",
        "POST /v1/social/post trusted actor post",
        async () =>
          postJson<{ decision: string; postId: string }>(`${APP_GATEWAY_BASE_URL}/v1/social/post`, {
            subjectDid: trustedActor.did,
            content: "Trusted flow actor post",
            presentation: trustedPostPresentation,
            nonce: trustedPostRequirements.challenge.nonce,
            audience: trustedPostRequirements.challenge.audience
          })
      );
      assert.equal(trustedPost.decision, "ALLOW");
      const trustedJoinRequirements = await requestJson<{
        challenge: { nonce: string; audience: string };
        requirements: Array<{
          vct: string;
          disclosures?: string[];
          predicates?: Array<{ path: string; op: string; value?: unknown }>;
        }>;
      }>(socialRequirementsUrl("social.space.join", { spaceId: createdSpace.spaceId }));
      const trustedJoinCredential = await issueCredentialFor({
        subjectDid: trustedActor.did,
        vct: trustedJoinRequirements.requirements[0].vct,
        claims: {
          member: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const trustedJoinPresentation = await buildPresentation({
        sdJwt: trustedJoinCredential.credential,
        disclose: buildDisclosureList(trustedJoinRequirements.requirements[0]),
        nonce: trustedJoinRequirements.challenge.nonce,
        audience: trustedJoinRequirements.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      await runSocialPhase(
        "flow actor join",
        "POST /v1/social/space/join second actor",
        async () => {
          const result = await postJson<{ decision: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/join`,
            {
              subjectDid: trustedActor.did,
              spaceId: createdSpace.spaceId,
              presentation: trustedJoinPresentation,
              nonce: trustedJoinRequirements.challenge.nonce,
              audience: trustedJoinRequirements.challenge.audience
            }
          );
          assert.equal(result.decision, "ALLOW");
        }
      );
      const trustedActorHash = createHmacSha256Pseudonymizer({
        pepper: PSEUDONYMIZER_PEPPER
      }).didToHash(trustedActor.did);
      const socialAuraRows = [
        {
          subject_did_hash: socialSubjectHash,
          domain: "social",
          state: { tier: "bronze", score: 3, diversity: 1 },
          updated_at: new Date().toISOString()
        },
        {
          subject_did_hash: trustedActorHash,
          domain: "social",
          state: { tier: "silver", score: 15, diversity: 3 },
          updated_at: new Date().toISOString()
        }
      ];
      for (const row of socialAuraRows) {
        await db("aura_state")
          .insert(row)
          .onConflict(["subject_did_hash", "domain"])
          .merge({ state: row.state, updated_at: row.updated_at });
      }
      const trustedActorSpacePoster = await issueSpaceCredential("social.space.post.create", {
        poster: true,
        tier: "silver",
        domain: `space:${createdSpace.spaceId}`,
        space_id: createdSpace.spaceId,
        as_of: new Date().toISOString()
      });
      const trustedSpacePost = await runSocialPhase(
        "space flow trusted actor post",
        "POST /v1/social/space/post trusted actor in target space",
        async () =>
          postJson<{ decision: string; spacePostId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/post`,
            {
              subjectDid: trustedActor.did,
              spaceId: createdSpace.spaceId,
              content: "Trusted actor space post for space flow ranking.",
              presentation: trustedActorSpacePoster.presentation,
              nonce: trustedActorSpacePoster.requirements.challenge.nonce,
              audience: trustedActorSpacePoster.requirements.challenge.audience
            }
          )
      );
      assert.equal(trustedSpacePost.decision, "ALLOW");
      await runSocialPhase(
        "flow feed trusted lens",
        "GET /v1/social/feed/flow trust=trusted_creator includes trusted actor",
        async () => {
          const baselineFlowEndpoint = `${APP_GATEWAY_BASE_URL}/v1/social/feed/flow?viewerDid=${encodeURIComponent(
            socialHolderDid
          )}&limit=20`;
          const baselineReady = await waitForSocialDbRow(
            "flow feed trusted lens",
            "baseline_flow_author_visibility",
            async () => {
              const baselineFeed = await requestJson<{
                posts: Array<{ post_id: string; trust_stamps?: string[] }>;
              }>(baselineFlowEndpoint);
              const baselinePostIds = baselineFeed.posts.map((entry) => entry.post_id);
              const baselineRows = baselinePostIds.length
                ? ((await db("social_posts")
                    .whereIn("post_id", baselinePostIds)
                    .select("post_id", "author_subject_did_hash")) as Array<{
                    post_id: string;
                    author_subject_did_hash: string;
                  }>)
                : [];
              const authorPrefixes = Array.from(
                new Set(baselineRows.map((row) => hashPrefix(row.author_subject_did_hash)))
              );
              console.log(
                `[diag] baseline_flow_response count=${baselineFeed.posts.length} post_ids=${JSON.stringify(
                  baselinePostIds
                )} author_hash_prefixes=${JSON.stringify(authorPrefixes)}`
              );
              if (baselineFeed.posts.length === 0) {
                console.log("[diag] baseline_flow_response empty feed");
              }
              const hasTrustedActorPostInBaseline =
                baselineFeed.posts.some((entry) => entry.post_id === trustedPost.postId) ||
                baselineRows.some((row) => row.author_subject_did_hash === trustedActorHash);
              if (hasTrustedActorPostInBaseline) {
                return { feedCount: baselineFeed.posts.length, reason: "baseline_flow_visible" };
              }
              const [trustedActorPostCountRow, trustedActorSignalCountRow] = await Promise.all([
                db("social_posts")
                  .where({ author_subject_did_hash: trustedActorHash })
                  .whereNull("deleted_at")
                  .count<{ count: string }>("post_id as count")
                  .first(),
                db("aura_signals")
                  .where({ subject_did_hash: trustedActorHash })
                  .whereIn("signal", ["social.post_success", "social.reply_success"])
                  .count<{ count: string }>("id as count")
                  .first()
              ]);
              const trustedActorPostCount = Number(trustedActorPostCountRow?.count ?? 0);
              const trustedActorSignalCount = Number(trustedActorSignalCountRow?.count ?? 0);
              console.log(
                `[diag] signal_feed_fallback posts=${trustedActorPostCount} signals=${trustedActorSignalCount}`
              );
              if (trustedActorPostCount >= 1 && trustedActorSignalCount >= 1) {
                return { feedCount: baselineFeed.posts.length, reason: "signal_feed_visible" };
              }
              return null;
            },
            120_000,
            2_000
          );
          console.log(
            `[social.wait.ok] gate=baseline_flow_author_visibility reason=${baselineReady?.reason ?? "unknown"} feed_count=${baselineReady?.feedCount ?? 0}`
          );

          let trustedSocialTier = await getAuraTierForDomain(trustedActorHash, "social");
          let expectedPostSignalCount = Number(
            (
              await db("aura_signals")
                .where({ subject_did_hash: trustedActorHash, signal: "social.post_success" })
                .count<{ count: string }>("id as count")
                .first()
            )?.count ?? 0
          );
          for (
            let actionIndex = 0;
            actionIndex < 2 && trustedSocialTier === "bronze";
            actionIndex += 1
          ) {
            console.log(
              `[diag] trusted_creator_boost start index=${actionIndex + 1} social_tier_before=${trustedSocialTier}`
            );
            const extraPostRequirements = await ensureRequirements(
              "social.post.create",
              await requestJson<{
                challenge: { nonce: string; audience: string };
                requirements: Array<{
                  vct: string;
                  disclosures?: string[];
                  predicates?: Array<{ path: string; op: string; value?: unknown }>;
                }>;
              }>(socialRequirementsUrl("social.post.create"))
            );
            const extraPostPresentation = await buildPresentation({
              sdJwt: trustedActor.baseCredential.credential,
              disclose: buildDisclosureList(extraPostRequirements.requirements[0]),
              nonce: extraPostRequirements.challenge.nonce,
              audience: extraPostRequirements.challenge.audience,
              holderJwk: trustedActor.keys.publicJwk,
              holderKey: trustedActor.keys.cryptoKey
            });
            const extraPost = await postJson<{ decision: string; postId: string }>(
              `${APP_GATEWAY_BASE_URL}/v1/social/post`,
              {
                subjectDid: trustedActor.did,
                content: `Trusted flow boost post ${actionIndex + 1} for deterministic silver readiness.`,
                visibility: "public",
                presentation: extraPostPresentation,
                nonce: extraPostRequirements.challenge.nonce,
                audience: extraPostRequirements.challenge.audience
              }
            );
            assert.equal(extraPost.decision, "ALLOW");
            expectedPostSignalCount += 1;
            await waitForSocialDbRow(
              "flow feed trusted lens",
              `trusted_actor_post_success_${actionIndex + 1}`,
              async () => {
                const signalCount = await db("aura_signals")
                  .where({ subject_did_hash: trustedActorHash, signal: "social.post_success" })
                  .count<{ count: string }>("id as count")
                  .first();
                return Number(signalCount?.count ?? 0) >= expectedPostSignalCount
                  ? signalCount
                  : null;
              },
              120_000,
              2_000
            );
            trustedSocialTier = await getAuraTierForDomain(trustedActorHash, "social");
            console.log(
              `[diag] trusted_creator_boost progress index=${actionIndex + 1} social_tier_after=${trustedSocialTier}`
            );
          }
          const tierReady = await waitForDbRow(
            db,
            async () => {
              const socialTier = await getAuraTierForDomain(trustedActorHash, "social");
              console.log(`[diag] trusted_creator_tier_check social_tier=${socialTier}`);
              if (socialTier === "silver" || socialTier === "gold") {
                return { socialTier };
              }
              return null;
            },
            "social:trusted_creator_social_tier_silver",
            240_000,
            {
              pollMs: 2_000,
              onTimeout: async () => {
                await emitSocialTimeoutDiagnostics(db, "flow feed trusted lens");
                try {
                  const diagnostic = (await Promise.race([
                    (async () => {
                      const countRow = await db("aura_state")
                        .where({ subject_did_hash: trustedActorHash, domain: "social" })
                        .count<{ count: string }>("subject_did_hash as count")
                        .first();
                      const row = (await db("aura_state")
                        .where({ subject_did_hash: trustedActorHash, domain: "social" })
                        .select("state")
                        .first()) as { state?: unknown } | undefined;
                      return {
                        rowCount: Number(countRow?.count ?? 0),
                        tier: row?.state ? parseAuraTier(row.state) : "none"
                      };
                    })(),
                    sleep(1_500).then(() => {
                      throw new Error("diagnostic_timeout");
                    })
                  ])) as { rowCount: number; tier: string };
                  console.error(
                    `[diag] trusted_creator_social_tier_silver_timeout subject_hash_prefix=${hashPrefix(
                      trustedActorHash
                    )} aura_state_rows=${diagnostic.rowCount} aura_state_tier=${diagnostic.tier}`
                  );
                } catch {
                  console.error(
                    `[diag] trusted_creator_social_tier_silver_timeout subject_hash_prefix=${hashPrefix(
                      trustedActorHash
                    )} diagnostic_failed`
                  );
                }
              }
            }
          );
          console.log(
            `[social.wait.ok] gate=trusted_creator_social_tier_silver social_tier=${tierReady?.socialTier ?? "bronze"}`
          );

          await logTrustedLensAuthorInputs({
            viewerSubjectHash: socialSubjectHash,
            targetAuthorHash: trustedActorHash,
            spaceId: createdSpace.spaceId
          });

          let seen = false;
          for (let attempt = 0; attempt < 10; attempt += 1) {
            const flowFeed = await requestJson<{
              posts: Array<{ post_id: string; trust_stamps?: string[] }>;
            }>(
              `${APP_GATEWAY_BASE_URL}/v1/social/feed/flow?viewerDid=${encodeURIComponent(socialHolderDid)}&trust=trusted_creator&limit=20`
            );
            await logFlowFeedSummary({
              trust: "trusted_creator",
              spaceId: createdSpace.spaceId,
              viewerSubjectHash: socialSubjectHash,
              targetAuthorHash: trustedActorHash,
              posts: flowFeed.posts
            });
            if (flowFeed.posts.some((entry) => entry.post_id === trustedPost.postId)) {
              seen = true;
              break;
            }
            await sleep(250);
          }
          assert.equal(seen, true);
        }
      );
      await runSocialPhase(
        "flow feed space lens",
        "GET /v1/social/feed/flow trust=space_members contains shared-space author",
        async () => {
          const baselineFlowEndpoint = `${APP_GATEWAY_BASE_URL}/v1/social/feed/flow?viewerDid=${encodeURIComponent(
            socialHolderDid
          )}&limit=20`;
          const baselineSpaceFlowEndpoint = `${APP_GATEWAY_BASE_URL}/v1/social/space/flow?spaceId=${encodeURIComponent(
            createdSpace.spaceId
          )}&viewerDid=${encodeURIComponent(socialHolderDid)}&limit=20`;
          await waitForSocialDbRow(
            "flow feed space lens",
            "space_members_readiness",
            async () => {
              const [viewerMembership, authorMembership, authorSpacePost] = await Promise.all([
                db("social_space_memberships")
                  .where({
                    subject_did_hash: socialSubjectHash,
                    space_id: createdSpace.spaceId,
                    status: "ACTIVE"
                  })
                  .first(),
                db("social_space_memberships")
                  .where({
                    subject_did_hash: trustedActorHash,
                    space_id: createdSpace.spaceId,
                    status: "ACTIVE"
                  })
                  .first(),
                db("social_space_posts")
                  .where({
                    space_id: createdSpace.spaceId,
                    author_subject_did_hash: trustedActorHash
                  })
                  .whereNull("deleted_at")
                  .first()
              ]);
              if (!viewerMembership || !authorMembership || !authorSpacePost) {
                return null;
              }
              const [baselineFlowFeed, baselineSpaceFlow] = await Promise.all([
                requestJson<{
                  posts: Array<{ post_id: string; trust_stamps?: string[] }>;
                }>(baselineFlowEndpoint),
                requestJson<{
                  posts: Array<{ space_post_id: string; trust_stamps?: string[] }>;
                }>(baselineSpaceFlowEndpoint)
              ]);
              await logFlowFeedSummary({
                trust: "space_members",
                spaceId: createdSpace.spaceId,
                viewerSubjectHash: socialSubjectHash,
                targetAuthorHash: trustedActorHash,
                posts: baselineFlowFeed.posts
              });
              await logSpaceFlowSummary({
                endpoint: baselineSpaceFlowEndpoint,
                trust: "none",
                spaceId: createdSpace.spaceId,
                viewerSubjectHash: socialSubjectHash,
                targetAuthorHash: trustedActorHash,
                posts: baselineSpaceFlow.posts
              });
              const baselineFlowHasExpectedPost = baselineFlowFeed.posts.some(
                (entry) => entry.post_id === trustedPost.postId
              );
              const baselineSpaceFlowHasExpectedPost = baselineSpaceFlow.posts.some(
                (entry) => entry.space_post_id === trustedSpacePost.spacePostId
              );
              console.log(
                `[diag] flow_space_lens_readiness space_id=${createdSpace.spaceId} viewer_hash_prefix=${hashPrefix(
                  socialSubjectHash
                )} author_hash_prefix=${hashPrefix(
                  trustedActorHash
                )} baseline_flow_count=${baselineFlowFeed.posts.length} space_flow_count=${
                  baselineSpaceFlow.posts.length
                } baseline_flow_has_expected=${baselineFlowHasExpectedPost} space_flow_has_expected=${baselineSpaceFlowHasExpectedPost}`
              );
              if (!baselineFlowHasExpectedPost || !baselineSpaceFlowHasExpectedPost) {
                return null;
              }
              return {
                ready: true,
                baselineFlowCount: baselineFlowFeed.posts.length,
                baselineSpaceFlowCount: baselineSpaceFlow.posts.length
              };
            },
            // Testnet flakiness: allow more time for social feed/space lens materialization.
            240_000,
            3_000
          );
          await logSpaceLensInputs({
            viewerSubjectHash: socialSubjectHash,
            targetAuthorHash: trustedActorHash,
            spaceId: createdSpace.spaceId
          });
          let seen = false;
          for (let attempt = 0; attempt < 10; attempt += 1) {
            const flowFeed = await requestJson<{
              posts: Array<{ post_id: string; trust_stamps?: string[] }>;
            }>(
              `${APP_GATEWAY_BASE_URL}/v1/social/feed/flow?viewerDid=${encodeURIComponent(socialHolderDid)}&trust=space_members&limit=20`
            );
            await logFlowFeedSummary({
              trust: "space_members",
              spaceId: createdSpace.spaceId,
              viewerSubjectHash: socialSubjectHash,
              targetAuthorHash: trustedActorHash,
              posts: flowFeed.posts
            });
            if (flowFeed.posts.some((entry) => entry.post_id === trustedPost.postId)) {
              seen = true;
              break;
            }
            await sleep(250);
          }
          assert.equal(seen, true);
        }
      );
      await runSocialPhase(
        "flow feed strict safety",
        "GET /v1/social/feed/flow safety=strict excludes low trust",
        async () => {
          const flowFeed = await requestJson<{ posts: Array<{ post_id: string }> }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/feed/flow?viewerDid=${encodeURIComponent(socialHolderDid)}&safety=strict&limit=20`
          );
          assert.equal(
            flowFeed.posts.some((entry) => entry.post_id === postAllowed.postId),
            false
          );
        }
      );
      await runSocialPhase(
        "space flow trusted lens",
        "GET /v1/social/space/flow trust=trusted_creator includes trusted space author",
        async () => {
          const trustedSpaceFlowEndpoint = `${APP_GATEWAY_BASE_URL}/v1/social/space/flow?spaceId=${encodeURIComponent(
            createdSpace.spaceId
          )}&viewerDid=${encodeURIComponent(socialHolderDid)}&trust=trusted_creator&limit=20`;
          const baselineSpaceFlowEndpoint = `${APP_GATEWAY_BASE_URL}/v1/social/space/flow?spaceId=${encodeURIComponent(
            createdSpace.spaceId
          )}&viewerDid=${encodeURIComponent(socialHolderDid)}&limit=20`;
          await waitForSocialDbRow(
            "space flow trusted lens",
            "space_flow_baseline_visibility",
            async () => {
              const [viewerMembership, authorPostInSpace] = await Promise.all([
                db("social_space_memberships")
                  .where({
                    subject_did_hash: socialSubjectHash,
                    space_id: createdSpace.spaceId,
                    status: "ACTIVE"
                  })
                  .first(),
                db("social_space_posts")
                  .where({
                    space_id: createdSpace.spaceId,
                    author_subject_did_hash: trustedActorHash
                  })
                  .whereNull("deleted_at")
                  .first()
              ]);
              if (!viewerMembership || !authorPostInSpace) {
                return null;
              }
              const baselineFlow = await requestJson<{
                posts: Array<{ space_post_id: string; trust_stamps?: string[] }>;
              }>(baselineSpaceFlowEndpoint);
              const baselinePostIds = baselineFlow.posts.map((entry) => entry.space_post_id);
              const baselineRows = baselinePostIds.length
                ? ((await db("social_space_posts")
                    .whereIn("space_post_id", baselinePostIds)
                    .select("space_post_id", "author_subject_did_hash")) as Array<{
                    space_post_id: string;
                    author_subject_did_hash: string;
                  }>)
                : [];
              const baselineAuthorPrefixes = Array.from(
                new Set(baselineRows.map((row) => hashPrefix(row.author_subject_did_hash)))
              );
              await logSpaceFlowSummary({
                endpoint: baselineSpaceFlowEndpoint,
                trust: "none",
                spaceId: createdSpace.spaceId,
                viewerSubjectHash: socialSubjectHash,
                targetAuthorHash: trustedActorHash,
                posts: baselineFlow.posts
              });
              const baselineContainsTargetPost = baselineFlow.posts.some(
                (entry) => entry.space_post_id === trustedSpacePost.spacePostId
              );
              const baselineContainsAuthor = baselineRows.some(
                (row) => row.author_subject_did_hash === trustedActorHash
              );
              console.log(
                `[diag] space_flow_baseline_visibility space_id=${createdSpace.spaceId} viewer_hash_prefix=${hashPrefix(
                  socialSubjectHash
                )} author_hash_prefix=${hashPrefix(
                  trustedActorHash
                )} response_count=${baselineFlow.posts.length} post_ids=${JSON.stringify(
                  baselinePostIds
                )} author_hash_prefixes=${JSON.stringify(
                  baselineAuthorPrefixes
                )} baseline_contains_target_post=${baselineContainsTargetPost} baseline_contains_author=${baselineContainsAuthor}`
              );
              if (!baselineContainsTargetPost && !baselineContainsAuthor) {
                return null;
              }
              return {
                ready: true,
                reason: baselineContainsTargetPost
                  ? "baseline_contains_target_post"
                  : "baseline_contains_author"
              };
            },
            240_000,
            2_000
          );
          const trustedReadiness = await waitForSocialDbRow(
            "space flow trusted lens",
            "space_flow_trusted_readiness",
            async () => {
              const [viewerMembership, authorPostInSpace] = await Promise.all([
                db("social_space_memberships")
                  .where({
                    subject_did_hash: socialSubjectHash,
                    space_id: createdSpace.spaceId,
                    status: "ACTIVE"
                  })
                  .first(),
                db("social_space_posts")
                  .where({
                    space_id: createdSpace.spaceId,
                    author_subject_did_hash: trustedActorHash
                  })
                  .whereNull("deleted_at")
                  .first()
              ]);
              if (!viewerMembership || !authorPostInSpace) {
                return null;
              }
              const trustedFlow = await requestJson<{
                posts: Array<{ space_post_id: string; trust_stamps?: string[] }>;
              }>(trustedSpaceFlowEndpoint);
              const trustedPostIds = trustedFlow.posts.map((entry) => entry.space_post_id);
              const trustedRows = trustedPostIds.length
                ? ((await db("social_space_posts")
                    .whereIn("space_post_id", trustedPostIds)
                    .select("space_post_id", "author_subject_did_hash")) as Array<{
                    space_post_id: string;
                    author_subject_did_hash: string;
                  }>)
                : [];
              const trustedAuthorPrefixes = Array.from(
                new Set(trustedRows.map((row) => hashPrefix(row.author_subject_did_hash)))
              );
              const trustedLensContainsTargetPost = trustedFlow.posts.some(
                (entry) => entry.space_post_id === trustedSpacePost.spacePostId
              );
              const trustedLensContainsAuthor = trustedRows.some(
                (row) => row.author_subject_did_hash === trustedActorHash
              );
              await logSpaceFlowSummary({
                endpoint: trustedSpaceFlowEndpoint,
                trust: "trusted_creator",
                spaceId: createdSpace.spaceId,
                viewerSubjectHash: socialSubjectHash,
                targetAuthorHash: trustedActorHash,
                posts: trustedFlow.posts
              });
              if (trustedLensContainsTargetPost || trustedLensContainsAuthor) {
                console.log(
                  `[diag] space_flow_trusted_readiness space_id=${createdSpace.spaceId} viewer_hash_prefix=${hashPrefix(
                    socialSubjectHash
                  )} author_hash_prefix=${hashPrefix(
                    trustedActorHash
                  )} response_count=${trustedFlow.posts.length} post_ids=${JSON.stringify(
                    trustedPostIds
                  )} author_hash_prefixes=${JSON.stringify(
                    trustedAuthorPrefixes
                  )} target_seen_by_post_id=${trustedLensContainsTargetPost} target_seen_by_author=${trustedLensContainsAuthor} social_tier=unknown space_tier=unknown trusted_creator_credential=unknown issuance_queue_row=unknown issuance_queue_status=unknown`
                );
                return {
                  ready: true,
                  reason: "lens_contains_target",
                  lensMatchedBy: trustedLensContainsTargetPost
                    ? "space_post_id"
                    : "author_subject_hash"
                };
              }
              const [socialTier, spaceTier, trustedCreatorCredential, trustedCreatorQueueRow] =
                await Promise.all([
                  getAuraTierForDomain(trustedActorHash, "social"),
                  getAuraTierForDomain(trustedActorHash, `space:${createdSpace.spaceId}`),
                  hasTrustedCreatorCredential(trustedActorHash),
                  db("aura_issuance_queue")
                    .where({
                      subject_did_hash: trustedActorHash,
                      output_vct: "cuncta.social.trusted_creator"
                    })
                    .whereIn("status", ["PENDING", "PROCESSING", "ISSUED"])
                    .orderBy("created_at", "desc")
                    .first()
                ]);
              const tierReady =
                socialTier === "silver" ||
                socialTier === "gold" ||
                spaceTier === "silver" ||
                spaceTier === "gold";
              const queueReady = Boolean(trustedCreatorQueueRow);
              console.log(
                `[diag] space_flow_trusted_readiness space_id=${createdSpace.spaceId} viewer_hash_prefix=${hashPrefix(
                  socialSubjectHash
                )} author_hash_prefix=${hashPrefix(
                  trustedActorHash
                )} response_count=${trustedFlow.posts.length} post_ids=${JSON.stringify(
                  trustedPostIds
                )} author_hash_prefixes=${JSON.stringify(
                  trustedAuthorPrefixes
                )} target_seen_by_post_id=${trustedLensContainsTargetPost} target_seen_by_author=${trustedLensContainsAuthor} social_tier=${socialTier} space_tier=${spaceTier} trusted_creator_credential=${trustedCreatorCredential} issuance_queue_row=${queueReady} issuance_queue_status=${String(
                  trustedCreatorQueueRow?.status ?? "none"
                )}`
              );
              if (tierReady || trustedCreatorCredential || queueReady) {
                return {
                  ready: true,
                  reason: tierReady
                    ? "tier>=silver"
                    : trustedCreatorCredential
                      ? "trusted_creator_credential"
                      : "issuance_queue_row",
                  socialTier,
                  spaceTier,
                  trustedCreatorCredential,
                  queueReady
                };
              }
              return null;
            },
            240_000,
            2_000
          );
          console.log(
            `[social.wait.ok] gate=space_flow_trusted_readiness reason=${trustedReadiness?.reason ?? "unknown"} social_tier=${trustedReadiness?.socialTier ?? "unknown"} space_tier=${trustedReadiness?.spaceTier ?? "unknown"} trusted_creator_credential=${String(
              trustedReadiness?.trustedCreatorCredential ?? "unknown"
            )} issuance_queue_row=${String(trustedReadiness?.queueReady ?? "unknown")}`
          );
          await logTrustedLensAuthorInputs({
            viewerSubjectHash: socialSubjectHash,
            targetAuthorHash: trustedActorHash,
            spaceId: createdSpace.spaceId
          });
          await logSpaceLensInputs({
            viewerSubjectHash: socialSubjectHash,
            targetAuthorHash: trustedActorHash,
            spaceId: createdSpace.spaceId
          });
          await waitForSocialDbRow(
            "space flow trusted lens",
            "space_flow_trusted_assertion_visibility",
            async () => {
              const flowFeed = await requestJson<{
                posts: Array<{ space_post_id: string; trust_stamps?: string[] }>;
              }>(trustedSpaceFlowEndpoint);
              await logSpaceFlowSummary({
                endpoint: trustedSpaceFlowEndpoint,
                trust: "trusted_creator",
                spaceId: createdSpace.spaceId,
                viewerSubjectHash: socialSubjectHash,
                targetAuthorHash: trustedActorHash,
                posts: flowFeed.posts
              });
              const trustedPostIds = flowFeed.posts.map((entry) => entry.space_post_id);
              const targetSeen = flowFeed.posts.some(
                (entry) => entry.space_post_id === trustedSpacePost.spacePostId
              );
              console.log(
                `[diag] space_flow_trusted_assertion_visibility space_id=${createdSpace.spaceId} viewer_hash_prefix=${hashPrefix(
                  socialSubjectHash
                )} author_hash_prefix=${hashPrefix(
                  trustedActorHash
                )} response_count=${flowFeed.posts.length} post_ids=${JSON.stringify(
                  trustedPostIds
                )} target_seen=${targetSeen}`
              );
              return targetSeen ? { ready: true, reason: "assertion_target_visible" } : null;
            },
            240_000,
            2_000
          );
          const flowFeed = await requestJson<{
            posts: Array<{ space_post_id: string; trust_stamps?: string[] }>;
          }>(trustedSpaceFlowEndpoint);
          await logSpaceFlowSummary({
            endpoint: trustedSpaceFlowEndpoint,
            trust: "trusted_creator",
            spaceId: createdSpace.spaceId,
            viewerSubjectHash: socialSubjectHash,
            targetAuthorHash: trustedActorHash,
            posts: flowFeed.posts
          });
          assert.ok(
            flowFeed.posts.some((entry) => entry.space_post_id === trustedSpacePost.spacePostId)
          );
        }
      );
      await runSocialPhase(
        "flow explain",
        "GET /v1/social/post/:postId/explain returns user-safe reasons",
        async () => {
          const explain = await requestJson<{
            reasons: string[];
            trustStampSummary?: { tier?: string; capability?: string; domain?: string };
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/post/${encodeURIComponent(trustedPost.postId)}/explain?viewerDid=${encodeURIComponent(
              socialHolderDid
            )}&feedMode=flow&trust=trusted_creator&safety=strict`
          );
          assert.ok(explain.reasons.length > 0);
          assert.ok(
            ["bronze", "silver", "gold"].includes(
              String(explain.trustStampSummary?.tier ?? "bronze")
            )
          );
        }
      );

      const spacePosterCredential = await issueSpaceCredential("social.space.post.create", {
        poster: true,
        tier: "silver",
        domain: spaceDomain,
        space_id: createdSpace.spaceId,
        as_of: new Date().toISOString()
      });
      await runSocialPhase(
        "space verifier binding positive",
        "POST /v1/verify social.space.post.create decision=ALLOW (context space A)",
        async () => {
          const verifyReq = await requestJson<{
            context?: { space_id?: string };
            challenge: { nonce: string; audience: string };
          }>(
            policyRequirementsUrl("social.space.post.create", {
              spaceId: createdSpace.spaceId,
              origin: gatewayOrigin
            })
          );
          assert.equal(verifyReq.context?.space_id, createdSpace.spaceId);
          const verifyPresentation = await buildPresentation({
            sdJwt: (
              await issueCredentialFor({
                subjectDid: socialHolderDid,
                vct: "cuncta.social.space.poster",
                claims: {
                  poster: true,
                  tier: "silver",
                  domain: `space:${createdSpace.spaceId}`,
                  space_id: createdSpace.spaceId,
                  as_of: new Date().toISOString()
                }
              })
            ).credential,
            disclose: ["poster", "space_id", "tier"],
            nonce: verifyReq.challenge.nonce,
            audience: verifyReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const verify = await postJson<VerifyResponse>(
            `${verifyBaseUrl}/v1/verify?action=${encodeURIComponent("social.space.post.create")}`,
            {
              presentation: verifyPresentation,
              nonce: verifyReq.challenge.nonce,
              audience: verifyReq.challenge.audience,
              context: verifyReq.context
            }
          );
          assert.equal(verify.decision, "ALLOW");
        }
      );
      await runSocialPhase(
        "space verifier binding negative",
        "POST /v1/verify social.space.post.create DENY space_context_mismatch",
        async () => {
          const verifyReq = await requestJson<{
            context?: { space_id?: string };
            challenge: { nonce: string; audience: string };
          }>(
            policyRequirementsUrl("social.space.post.create", {
              spaceId: createdSpaceB.spaceId,
              origin: gatewayOrigin
            })
          );
          assert.equal(verifyReq.context?.space_id, createdSpaceB.spaceId);
          const verifyPresentation = await buildPresentation({
            sdJwt: (
              await issueCredentialFor({
                subjectDid: socialHolderDid,
                vct: "cuncta.social.space.poster",
                claims: {
                  poster: true,
                  tier: "silver",
                  domain: `space:${createdSpace.spaceId}`,
                  space_id: createdSpace.spaceId,
                  as_of: new Date().toISOString()
                }
              })
            ).credential,
            disclose: ["poster", "space_id", "tier"],
            nonce: verifyReq.challenge.nonce,
            audience: verifyReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const verify = await postJson<VerifyResponse>(
            `${verifyBaseUrl}/v1/verify?action=${encodeURIComponent("social.space.post.create")}`,
            {
              presentation: verifyPresentation,
              nonce: verifyReq.challenge.nonce,
              audience: verifyReq.challenge.audience,
              context: verifyReq.context
            }
          );
          assert.equal(verify.decision, "DENY");
          if (INCLUDE_VERIFY_REASONS) {
            assert.ok(verify.reasons?.includes("space_context_mismatch"));
          }
        }
      );
      await runSocialPhase(
        "space post cross-space misuse",
        "POST /v1/social/space/post DENY using space A credential in space B",
        async () => {
          const deny = await fetch(`${APP_GATEWAY_BASE_URL}/v1/social/space/post`, {
            method: "POST",
            headers: { "content-type": "application/json", ...gatewayHeaders() },
            body: JSON.stringify({
              subjectDid: socialHolderDid,
              spaceId: createdSpaceB.spaceId,
              content: "Cross-space misuse attempt",
              presentation: spacePosterCredential.presentation,
              nonce: spacePosterCredential.requirements.challenge.nonce,
              audience: spacePosterCredential.requirements.challenge.audience
            })
          });
          assert.equal(deny.status, 403);
        }
      );
      // Challenges are consumed on first verification attempt now (even when DENY),
      // so we must mint a fresh nonce/audience for the subsequent valid post.
      const spacePosterCredentialFresh = await issueSpaceCredential("social.space.post.create", {
        poster: true,
        tier: "silver",
        domain: spaceDomain,
        space_id: createdSpace.spaceId,
        as_of: new Date().toISOString()
      });
      const spacePostAllowed = await runSocialPhase(
        "space post create",
        "POST /v1/social/space/post decision=ALLOW",
        async () =>
          postJson<{ decision: string; spacePostId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/post`,
            {
              subjectDid: socialHolderDid,
              spaceId: createdSpace.spaceId,
              content: "Space-first social signal post.",
              presentation: spacePosterCredentialFresh.presentation,
              nonce: spacePosterCredentialFresh.requirements.challenge.nonce,
              audience: spacePosterCredentialFresh.requirements.challenge.audience
            }
          )
      );
      assert.equal(spacePostAllowed.decision, "ALLOW");
      assert.ok(spacePostAllowed.spacePostId);
      const spaceReport = await runSocialPhase(
        "space report create",
        "POST /v1/social/report decision=ALLOW (space)",
        async () => {
          const requirements = await requestJson<{
            challenge: { nonce: string; audience: string };
            requirements: Array<{
              vct: string;
              disclosures?: string[];
              predicates?: Array<{ path: string; op: string; value?: unknown }>;
            }>;
          }>(socialRequirementsUrl("social.report.create"));
          const reportPresentation = await buildPresentation({
            sdJwt: socialBaseCredential.credential,
            disclose: buildDisclosureList(requirements.requirements[0]),
            nonce: requirements.challenge.nonce,
            audience: requirements.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          return postJson<{ decision: string; reportId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/report`,
            {
              subjectDid: socialHolderDid,
              spaceId: createdSpace.spaceId,
              targetSpacePostId: spacePostAllowed.spacePostId,
              reasonCode: "abuse",
              presentation: reportPresentation,
              nonce: requirements.challenge.nonce,
              audience: requirements.challenge.audience
            }
          );
        }
      );
      assert.equal(spaceReport.decision, "ALLOW");

      const spaceModeratorCredential = await issueSpaceCredential("social.space.moderate", {
        moderator: true,
        domain: spaceDomain,
        space_id: createdSpace.spaceId,
        as_of: new Date().toISOString()
      });
      const moderation = await runSocialPhase(
        "space moderate",
        "POST /v1/social/space/moderate decision=ALLOW",
        async () =>
          postJson<{ decision: string; moderationId: string; auditHash: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/moderate`,
            {
              subjectDid: socialHolderDid,
              spaceId: createdSpace.spaceId,
              operation: "remove_content",
              targetSpacePostId: spacePostAllowed.spacePostId,
              reasonCode: "policy_violation",
              anchor: true,
              presentation: spaceModeratorCredential.presentation,
              nonce: spaceModeratorCredential.requirements.challenge.nonce,
              audience: spaceModeratorCredential.requirements.challenge.audience
            }
          )
      );
      assert.equal(moderation.decision, "ALLOW");
      assert.ok(moderation.auditHash);
      await runSocialPhase(
        "moderation cases gated deny",
        "GET /v1/social/spaces/:spaceId/moderation/cases denied without moderator capability",
        async () => {
          const denied = await fetch(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/moderation/cases?subjectDid=${encodeURIComponent(
              socialHolderDid
            )}&presentation=${encodeURIComponent(spacePosterCredential.presentation)}&nonce=${encodeURIComponent(
              spacePosterCredential.requirements.challenge.nonce
            )}&audience=${encodeURIComponent(spacePosterCredential.requirements.challenge.audience)}`,
            { headers: gatewayHeaders() }
          );
          assert.equal(denied.status, 403);
        }
      );
      const freshModeratorCredential = await issueSpaceCredential("social.space.moderate", {
        moderator: true,
        domain: spaceDomain,
        space_id: createdSpace.spaceId,
        as_of: new Date().toISOString()
      });
      const moderationCases = await runSocialPhase(
        "moderation cases list",
        "GET /v1/social/spaces/:spaceId/moderation/cases returns open case for moderator",
        async () =>
          requestJson<{
            cases: Array<{
              case_id: string;
              report_id: string;
              status: "OPEN" | "ACK" | "RESOLVED";
            }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/moderation/cases?subjectDid=${encodeURIComponent(
              socialHolderDid
            )}&presentation=${encodeURIComponent(freshModeratorCredential.presentation)}&nonce=${encodeURIComponent(
              freshModeratorCredential.requirements.challenge.nonce
            )}&audience=${encodeURIComponent(freshModeratorCredential.requirements.challenge.audience)}`
          )
      );
      const openCase = moderationCases.cases.find(
        (entry) => entry.report_id === spaceReport.reportId && entry.status === "OPEN"
      );
      assert.ok(openCase, "expected open moderation case for space report");
      if (!openCase) {
        throw new Error("expected open moderation case for space report");
      }
      await runSocialPhase(
        "moderation case resolve",
        "POST /v1/social/spaces/:spaceId/moderation/cases/:caseId/resolve decision=ALLOW",
        async () => {
          const resolveModeratorCredential = await issueSpaceCredential("social.space.moderate", {
            moderator: true,
            domain: spaceDomain,
            space_id: createdSpace.spaceId,
            as_of: new Date().toISOString()
          });
          const resolved = await postJson<{ decision: string; status: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/moderation/cases/${encodeURIComponent(openCase.case_id)}/resolve`,
            {
              subjectDid: socialHolderDid,
              presentation: resolveModeratorCredential.presentation,
              nonce: resolveModeratorCredential.requirements.challenge.nonce,
              audience: resolveModeratorCredential.requirements.challenge.audience,
              anchor: true
            }
          );
          assert.equal(resolved.decision, "ALLOW");
          assert.equal(resolved.status, "RESOLVED");
        }
      );
      await runSocialPhase(
        "moderation audit view",
        "GET /v1/social/spaces/:spaceId/moderation/audit returns hash-only events",
        async () => {
          const auditModeratorCredential = await issueSpaceCredential("social.space.moderate", {
            moderator: true,
            domain: spaceDomain,
            space_id: createdSpace.spaceId,
            as_of: new Date().toISOString()
          });
          const audit = await requestJson<{
            actions: Array<{ audit_hash: string; operation: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/moderation/audit?subjectDid=${encodeURIComponent(
              socialHolderDid
            )}&presentation=${encodeURIComponent(auditModeratorCredential.presentation)}&nonce=${encodeURIComponent(
              auditModeratorCredential.requirements.challenge.nonce
            )}&audience=${encodeURIComponent(auditModeratorCredential.requirements.challenge.audience)}&limit=20`
          );
          assert.ok(audit.actions.length > 0);
          assert.ok(audit.actions.every((entry) => entry.audit_hash.length > 10));
        }
      );
      await runSocialPhase(
        "space moderation anchor confirm",
        "DB anchor_outbox SOCIAL_SPACE_MODERATION confirmed",
        async () => {
          await waitForSocialDbRow(
            "space moderation anchor confirm",
            "anchor_outbox.social_space_moderation.confirmed",
            async () =>
              db("anchor_outbox")
                .where({
                  payload_hash: moderation.auditHash,
                  event_type: "SOCIAL_SPACE_MODERATION"
                })
                .andWhere({ status: "CONFIRMED" })
                .first()
          );
        }
      );

      await runSocialPhase(
        "space feed moderation exclusion",
        "GET /v1/social/space/feed hides moderated post",
        async () => {
          const feed = await requestJson<{ posts: Array<{ space_post_id: string }> }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/feed?spaceId=${encodeURIComponent(createdSpace.spaceId)}&limit=20`
          );
          assert.equal(
            feed.posts.some((post) => post.space_post_id === spacePostAllowed.spacePostId),
            false
          );
        }
      );
      await runSocialPhase(
        "space analytics",
        "GET /v1/social/spaces/:spaceId/analytics returns trust-converted actions",
        async () => {
          const analytics = await requestJson<{
            trust_converted_actions?: {
              posts_total?: number;
              posts_trust_qualified?: number;
              posts_trust_conversion_rate?: number;
            };
            moderation_actions_total?: number;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/analytics?limit=30`
          );
          assert.ok((analytics.trust_converted_actions?.posts_total ?? 0) >= 1);
          assert.ok((analytics.trust_converted_actions?.posts_trust_qualified ?? 0) >= 0);
          assert.ok((analytics.trust_converted_actions?.posts_trust_conversion_rate ?? 0) >= 0);
          assert.ok((analytics.moderation_actions_total ?? 0) >= 1);
        }
      );

      const spacePostForErase = await runSocialPhase(
        "space post create (pre-erase)",
        "POST /v1/social/space/post second post",
        async () => {
          const freshSpacePosterCredential = await issueSpaceCredential(
            "social.space.post.create",
            {
              poster: true,
              tier: "silver",
              domain: spaceDomain,
              space_id: createdSpace.spaceId,
              as_of: new Date().toISOString()
            }
          );
          return postJson<{ decision: string; spacePostId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/post`,
            {
              subjectDid: socialHolderDid,
              spaceId: createdSpace.spaceId,
              content: "This post should disappear after erase.",
              presentation: freshSpacePosterCredential.presentation,
              nonce: freshSpacePosterCredential.requirements.challenge.nonce,
              audience: freshSpacePosterCredential.requirements.challenge.audience
            }
          );
        }
      );
      assert.equal(spacePostForErase.decision, "ALLOW");

      await runSocialPhase(
        "aura signal emission",
        "DB aura_signals social.post_success count >= 1",
        async () => {
          const row = await waitForSocialDbRow(
            "aura signal emission",
            "aura_signals.social.post_success",
            async () => {
              const result = await db("aura_signals")
                .where({ subject_did_hash: socialSubjectHash, signal: "social.post_success" })
                .count<{ count: string }>("id as count")
                .first();
              return Number(result?.count ?? 0) >= 1 ? result : null;
            }
          );
          assert.ok(row, "expected social aura signal");
        }
      );

      await runSocialPhase(
        "aura rule processing (queue/claim)",
        "DB aura_issuance_queue social domain pending/issued + POST /v1/aura/claim",
        async () => {
          const queueRow = (await waitForSocialDbRow(
            "aura rule processing (queue/claim)",
            "aura_issuance_queue.social",
            async () =>
              db("aura_issuance_queue")
                .where({ subject_did_hash: socialSubjectHash, domain: "social" })
                .whereIn("status", ["PENDING", "ISSUED"])
                .orderBy("created_at", "desc")
                .first()
          )) as { output_vct: string };
          const claim = await postJson<{ status: string }>(
            `${ISSUER_SERVICE_BASE_URL}/v1/aura/claim`,
            { subjectDid: socialHolderDid, output_vct: queueRow.output_vct },
            { Authorization: `Bearer ${serviceTokenIssuer}` }
          );
          assert.ok(["ISSUED", "ALREADY_ISSUED", "NOT_ELIGIBLE"].includes(claim.status));
        }
      );

      const emojiPackCreateReq = await runSocialPhase(
        "entertainment emoji deny->allow",
        "GET /v1/social/requirements media.emoji.pack.create",
        async () =>
          ensureRequirements(
            "media.emoji.pack.create",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("media.emoji.pack.create"))
          )
      );
      const emojiPackCreatePresentationWithoutCap = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(emojiPackCreateReq.requirements[0]),
        nonce: emojiPackCreateReq.challenge.nonce,
        audience: emojiPackCreateReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const deniedEmojiPackCreate = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/media/emoji/pack/create`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            subjectDid: socialHolderDid,
            spaceId: createdSpace.spaceId,
            visibility: "private",
            presentation: emojiPackCreatePresentationWithoutCap,
            nonce: emojiPackCreateReq.challenge.nonce,
            audience: emojiPackCreateReq.challenge.audience
          })
        }
      );
      assert.equal(deniedEmojiPackCreate.status, 403);

      // Challenges are consumed on first verify attempt now; re-mint for the ALLOW attempt.
      const emojiPackCreateReq2 = await ensureRequirements(
        "media.emoji.pack.create",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("media.emoji.pack.create"))
      );
      const emojiCreatorCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.media.emoji_creator",
        claims: {
          emoji_creator: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const emojiPackCreatePresentation = await buildPresentation({
        sdJwt: emojiCreatorCredential.credential,
        disclose: buildDisclosureList(emojiPackCreateReq2.requirements[0]),
        nonce: emojiPackCreateReq2.challenge.nonce,
        audience: emojiPackCreateReq2.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const emojiPackCreateAllowed = await postJson<{ decision: string; packId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/media/emoji/pack/create`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          visibility: "private",
          presentation: emojiPackCreatePresentation,
          nonce: emojiPackCreateReq2.challenge.nonce,
          audience: emojiPackCreateReq2.challenge.audience
        }
      );
      assert.equal(emojiPackCreateAllowed.decision, "ALLOW");

      const emojiPublishReq = await ensureRequirements(
        "media.emoji.pack.publish",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("media.emoji.pack.publish", { spaceId: createdSpace.spaceId }))
      );
      const emojiPublishPresentation = await buildPresentation({
        sdJwt: emojiCreatorCredential.credential,
        disclose: buildDisclosureList(emojiPublishReq.requirements[0]),
        nonce: emojiPublishReq.challenge.nonce,
        audience: emojiPublishReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const emojiPublish = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/media/emoji/pack/publish`,
        {
          subjectDid: socialHolderDid,
          packId: emojiPackCreateAllowed.packId,
          spaceId: createdSpace.spaceId,
          presentation: emojiPublishPresentation,
          nonce: emojiPublishReq.challenge.nonce,
          audience: emojiPublishReq.challenge.audience
        }
      );
      assert.equal(emojiPublish.decision, "ALLOW");

      const presenceReq = await ensureRequirements(
        "presence.set_mode",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("presence.set_mode", { spaceId: createdSpace.spaceId }))
      );
      const presenceCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.presence.mode_access",
        claims: {
          mode_access: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const presencePresentation = await buildPresentation({
        sdJwt: presenceCredential.credential,
        disclose: buildDisclosureList(presenceReq.requirements[0]),
        nonce: presenceReq.challenge.nonce,
        audience: presenceReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const presenceSet = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/presence/set_mode`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          mode: "active",
          presentation: presencePresentation,
          nonce: presenceReq.challenge.nonce,
          audience: presenceReq.challenge.audience
        }
      );
      assert.equal(presenceSet.decision, "ALLOW");
      const presenceState = await requestJson<{ states: Array<{ mode: string }> }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/presence/state?spaceId=${encodeURIComponent(createdSpace.spaceId)}`
      );
      assert.ok(presenceState.states.some((entry) => entry.mode === "active"));
      const presencePingReq = await ensureRequirements(
        "presence.ping",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("presence.ping", { spaceId: createdSpace.spaceId }))
      );
      const presencePingPresentation = await buildPresentation({
        sdJwt: presenceCredential.credential,
        disclose: buildDisclosureList(presencePingReq.requirements[0]),
        nonce: presencePingReq.challenge.nonce,
        audience: presencePingReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const presencePing = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/presence/ping`,
        {
          subjectDid: socialHolderDid,
          mode: "active",
          presentation: presencePingPresentation,
          nonce: presencePingReq.challenge.nonce,
          audience: presencePingReq.challenge.audience
        }
      );
      assert.equal(presencePing.decision, "ALLOW");
      const presenceStrip = await requestJson<{
        counts: { quiet: number; active: number; immersive: number };
      }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/presence?subjectDid=${encodeURIComponent(socialHolderDid)}`
      );
      assert.ok(presenceStrip.counts.active >= 1);

      const crewCreateReq = await ensureRequirements(
        "social.crew.create",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("social.crew.create", { spaceId: createdSpace.spaceId }))
      );
      const crewPosterCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.social.space.poster",
        claims: {
          poster: true,
          tier: "silver",
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const crewCreatePresentation = await buildPresentation({
        sdJwt: crewPosterCredential.credential,
        disclose: buildDisclosureList(crewCreateReq.requirements[0]),
        nonce: crewCreateReq.challenge.nonce,
        audience: crewCreateReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const createdCrew = await postJson<{ decision: string; crewId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/crews`,
        {
          subjectDid: socialHolderDid,
          name: "Alpha Crew",
          presentation: crewCreatePresentation,
          nonce: crewCreateReq.challenge.nonce,
          audience: crewCreateReq.challenge.audience
        }
      );
      assert.equal(createdCrew.decision, "ALLOW");
      const crewJoinReq = await ensureRequirements(
        "social.crew.join",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("social.crew.join", { spaceId: createdSpace.spaceId }))
      );
      const crewMemberCredential = await issueCredentialFor({
        subjectDid: trustedActor.did,
        vct: "cuncta.social.space.member",
        claims: {
          member: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const crewJoinPresentation = await buildPresentation({
        sdJwt: crewMemberCredential.credential,
        disclose: buildDisclosureList(crewJoinReq.requirements[0]),
        nonce: crewJoinReq.challenge.nonce,
        audience: crewJoinReq.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      const joinedCrew = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/crews/${encodeURIComponent(createdCrew.crewId)}/join`,
        {
          subjectDid: trustedActor.did,
          presentation: crewJoinPresentation,
          nonce: crewJoinReq.challenge.nonce,
          audience: crewJoinReq.challenge.audience
        }
      );
      assert.equal(joinedCrew.decision, "ALLOW");
      const crewPresence = await requestJson<{ active_count: number }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/crews/${encodeURIComponent(createdCrew.crewId)}/presence?subjectDid=${encodeURIComponent(socialHolderDid)}`
      );
      assert.ok(crewPresence.active_count >= 1);

      const challengeCreateReq = await ensureRequirements(
        "challenge.create",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("challenge.create", { spaceId: createdSpace.spaceId }))
      );
      const stewardCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.social.space.steward",
        claims: {
          steward: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const challengeCreatePresentation = await buildPresentation({
        sdJwt: stewardCredential.credential,
        disclose: buildDisclosureList(challengeCreateReq.requirements[0]),
        nonce: challengeCreateReq.challenge.nonce,
        audience: challengeCreateReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const createdChallenge = await postJson<{ decision: string; challengeId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/challenges`,
        {
          subjectDid: socialHolderDid,
          cadence: "daily",
          title: "Daily banter drop",
          durationHours: 1,
          presentation: challengeCreatePresentation,
          nonce: challengeCreateReq.challenge.nonce,
          audience: challengeCreateReq.challenge.audience
        }
      );
      assert.equal(createdChallenge.decision, "ALLOW");
      const challengeJoinReq = await ensureRequirements(
        "challenge.join",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("challenge.join", { spaceId: createdSpace.spaceId }))
      );
      const challengeMemberCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.social.space.member",
        claims: {
          member: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const challengeJoinPresentation = await buildPresentation({
        sdJwt: challengeMemberCredential.credential,
        disclose: buildDisclosureList(challengeJoinReq.requirements[0]),
        nonce: challengeJoinReq.challenge.nonce,
        audience: challengeJoinReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const joinedChallenge = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/challenges/${encodeURIComponent(createdChallenge.challengeId)}/join`,
        {
          subjectDid: socialHolderDid,
          presentation: challengeJoinPresentation,
          nonce: challengeJoinReq.challenge.nonce,
          audience: challengeJoinReq.challenge.audience
        }
      );
      assert.equal(joinedChallenge.decision, "ALLOW");
      const banterThreadCreateReq = await ensureRequirements(
        "banter.thread.create",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("banter.thread.create", { spaceId: createdSpace.spaceId }))
      );
      const banterThreadCreatePresentation = await buildPresentation({
        sdJwt: challengeMemberCredential.credential,
        disclose: buildDisclosureList(banterThreadCreateReq.requirements[0]),
        nonce: banterThreadCreateReq.challenge.nonce,
        audience: banterThreadCreateReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const banterThreadReadReq = await ensureRequirements(
        "banter.thread.read",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("banter.thread.read", { spaceId: createdSpace.spaceId }))
      );
      const banterReadPresentation = await buildPresentation({
        sdJwt: challengeMemberCredential.credential,
        disclose: buildDisclosureList(banterThreadReadReq.requirements[0]),
        nonce: banterThreadReadReq.challenge.nonce,
        audience: banterThreadReadReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const banterSendReq = await ensureRequirements(
        "banter.message.send",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("banter.message.send", { spaceId: createdSpace.spaceId }))
      );
      const banterSendPresentation = await buildPresentation({
        sdJwt: challengeMemberCredential.credential,
        disclose: buildDisclosureList(banterSendReq.requirements[0]),
        nonce: banterSendReq.challenge.nonce,
        audience: banterSendReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      await runSocialPhase(
        "banter thread + message flows",
        "space/crew/challenge banter create+send",
        async () => {
          const createBanterThread = async (input: {
            kind: "space_chat" | "crew_chat" | "challenge_chat";
            crewId?: string;
            challengeId?: string;
          }) => {
            const createReq = await ensureRequirements(
              "banter.thread.create",
              await requestJson<{
                challenge: { nonce: string; audience: string };
                requirements: Array<{
                  vct: string;
                  disclosures?: string[];
                  predicates?: Array<{ path: string; op: string; value?: unknown }>;
                }>;
              }>(socialRequirementsUrl("banter.thread.create", { spaceId: createdSpace.spaceId }))
            );
            const createPresentation = await buildPresentation({
              sdJwt: challengeMemberCredential.credential,
              disclose: buildDisclosureList(createReq.requirements[0]),
              nonce: createReq.challenge.nonce,
              audience: createReq.challenge.audience,
              holderJwk: socialHolderKeys.publicJwk,
              holderKey: socialHolderKeys.cryptoKey
            });
            return postJson<{ decision: string; threadId: string }>(
              `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/banter/threads`,
              {
                subjectDid: socialHolderDid,
                kind: input.kind,
                ...(input.crewId ? { crewId: input.crewId } : {}),
                ...(input.challengeId ? { challengeId: input.challengeId } : {}),
                presentation: createPresentation,
                nonce: createReq.challenge.nonce,
                audience: createReq.challenge.audience
              }
            );
          };
          const spaceThread = await createBanterThread({ kind: "space_chat" });
          assert.equal(spaceThread.decision, "ALLOW");
          const crewThread = await createBanterThread({
            kind: "crew_chat",
            crewId: createdCrew.crewId
          });
          assert.equal(crewThread.decision, "ALLOW");
          const challengeThread = await createBanterThread({
            kind: "challenge_chat",
            challengeId: createdChallenge.challengeId
          });
          assert.equal(challengeThread.decision, "ALLOW");
          const permission = await postJson<{
            decision: string;
            permissionToken: string;
            expiresAt: string;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/banter/threads/${encodeURIComponent(spaceThread.threadId)}/permission`,
            {
              subjectDid: socialHolderDid,
              presentation: banterReadPresentation,
              nonce: banterThreadReadReq.challenge.nonce,
              audience: banterThreadReadReq.challenge.audience
            }
          );
          assert.equal(permission.decision, "ALLOW");
          assert.ok(permission.permissionToken.length > 20);
          const sent = await postJson<{ decision: string; messageId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/banter/threads/${encodeURIComponent(spaceThread.threadId)}/send`,
            {
              subjectDid: socialHolderDid,
              bodyText: "Space banter line one.",
              permissionToken: permission.permissionToken,
              presentation: banterSendPresentation,
              nonce: banterSendReq.challenge.nonce,
              audience: banterSendReq.challenge.audience
            }
          );
          assert.equal(sent.decision, "ALLOW");
          assert.ok(sent.messageId);
          const list = await requestJson<{
            threads: Array<{ kind: string; thread_id: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/banter/threads`
          );
          assert.ok(
            list.threads.some(
              (entry) => entry.kind === "space_chat" && entry.thread_id === spaceThread.threadId
            )
          );
          const messages = await requestJson<{
            messages: Array<{ message_id: string; body_text?: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/banter/threads/${encodeURIComponent(spaceThread.threadId)}/messages?limit=20`
          );
          assert.ok(messages.messages.some((entry) => entry.message_id === sent.messageId));
        }
      );
      await db("social_space_streaks")
        .insert({
          space_id: createdSpace.spaceId,
          subject_hash: socialSubjectHash,
          streak_type: "daily_challenge",
          current_count: 1,
          best_count: 1,
          last_completed_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date().toISOString()
        })
        .onConflict(["space_id", "subject_hash", "streak_type"])
        .merge({
          current_count: 1,
          best_count: 1,
          last_completed_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
          updated_at: new Date().toISOString()
        });
      await runSocialPhase(
        "pulse overlay (pre-complete)",
        "GET /v1/social/spaces/:spaceId/pulse returns crew/challenge/streak cards",
        async () => {
          const pulseBeforeComplete = await requestJson<{
            cards?: Array<{ type?: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/pulse?subjectDid=${encodeURIComponent(
              socialHolderDid
            )}`
          );
          const pulseTypes = new Set((pulseBeforeComplete.cards ?? []).map((entry) => entry.type));
          assert.equal(pulseTypes.has("crew_active"), true);
          assert.equal(pulseTypes.has("challenge_ending"), true);
          assert.equal(pulseTypes.has("streak_risk"), true);
        }
      );
      const challengeCompleteReq = await ensureRequirements(
        "challenge.complete",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("challenge.complete", { spaceId: createdSpace.spaceId }))
      );
      const challengeCompletePresentation = await buildPresentation({
        sdJwt: challengeMemberCredential.credential,
        disclose: buildDisclosureList(challengeCompleteReq.requirements[0]),
        nonce: challengeCompleteReq.challenge.nonce,
        audience: challengeCompleteReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const completedChallenge = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/challenges/${encodeURIComponent(createdChallenge.challengeId)}/complete`,
        {
          subjectDid: socialHolderDid,
          presentation: challengeCompletePresentation,
          nonce: challengeCompleteReq.challenge.nonce,
          audience: challengeCompleteReq.challenge.audience
        }
      );
      assert.equal(completedChallenge.decision, "ALLOW");
      const streaks = await requestJson<{
        you: Array<{ streak_type: string; current_count: number }>;
      }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/streaks?subjectDid=${encodeURIComponent(socialHolderDid)}`
      );
      assert.ok(streaks.you.some((entry) => entry.streak_type === "daily_challenge"));

      const ritualCreateReq = await ensureRequirements(
        "ritual.create",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("ritual.create", { spaceId: createdSpace.spaceId }))
      );
      const ritualPosterCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.social.space.poster",
        claims: {
          poster: true,
          tier: "silver",
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const ritualCreatePresentation = await buildPresentation({
        sdJwt: ritualPosterCredential.credential,
        disclose: buildDisclosureList(ritualCreateReq.requirements[0]),
        nonce: ritualCreateReq.challenge.nonce,
        audience: ritualCreateReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const ritualCreated = await postJson<{ decision: string; ritualId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/ritual/create`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          title: "10-minute drop",
          description: "Post now",
          durationMinutes: 10,
          presentation: ritualCreatePresentation,
          nonce: ritualCreateReq.challenge.nonce,
          audience: ritualCreateReq.challenge.audience
        }
      );
      assert.equal(ritualCreated.decision, "ALLOW");
      const ritualJoinReq = await ensureRequirements(
        "ritual.participate",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("ritual.participate", { spaceId: createdSpace.spaceId }))
      );
      const ritualMemberCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.social.space.member",
        claims: {
          member: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const ritualJoinPresentation = await buildPresentation({
        sdJwt: ritualMemberCredential.credential,
        disclose: buildDisclosureList(ritualJoinReq.requirements[0]),
        nonce: ritualJoinReq.challenge.nonce,
        audience: ritualJoinReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const ritualJoined = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/ritual/participate`,
        {
          subjectDid: socialHolderDid,
          ritualId: ritualCreated.ritualId,
          spaceId: createdSpace.spaceId,
          presentation: ritualJoinPresentation,
          nonce: ritualJoinReq.challenge.nonce,
          audience: ritualJoinReq.challenge.audience
        }
      );
      assert.equal(ritualJoined.decision, "ALLOW");
      const ritualCompleteReq = await ensureRequirements(
        "ritual.complete",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("ritual.complete", { spaceId: createdSpace.spaceId }))
      );
      const ritualCompletePresentation = await buildPresentation({
        sdJwt: ritualMemberCredential.credential,
        disclose: buildDisclosureList(ritualCompleteReq.requirements[0]),
        nonce: ritualCompleteReq.challenge.nonce,
        audience: ritualCompleteReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const ritualCompleted = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/ritual/complete`,
        {
          subjectDid: socialHolderDid,
          ritualId: ritualCreated.ritualId,
          spaceId: createdSpace.spaceId,
          presentation: ritualCompletePresentation,
          nonce: ritualCompleteReq.challenge.nonce,
          audience: ritualCompleteReq.challenge.audience
        }
      );
      assert.equal(ritualCompleted.decision, "ALLOW");
      const leaderboardAfterRitual = await requestJson<{
        top_contributors: Array<{ signals?: { ritual_complete?: number } }>;
      }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/leaderboard?window=7d`
      );
      assert.ok(leaderboardAfterRitual.top_contributors.length >= 1);
      const visibilityReq = await ensureRequirements(
        "presence.ping",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("presence.ping", { spaceId: createdSpace.spaceId }))
      );
      const visibilityPresentation = await buildPresentation({
        sdJwt: presenceCredential.credential,
        disclose: buildDisclosureList(visibilityReq.requirements[0]),
        nonce: visibilityReq.challenge.nonce,
        audience: visibilityReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/profile/visibility`,
        {
          subjectDid: socialHolderDid,
          showOnLeaderboard: true,
          showOnPresence: false,
          presenceLabel: "social-holder",
          presentation: visibilityPresentation,
          nonce: visibilityReq.challenge.nonce,
          audience: visibilityReq.challenge.audience
        }
      );

      const huddleHostReq = await ensureRequirements(
        "sync.hangout.create_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.hangout.create_session", { spaceId: createdSpace.spaceId }))
      );
      const huddleHostCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.sync.huddle_host",
        claims: {
          huddle_host: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const huddleCreatePresentation = await buildPresentation({
        sdJwt: huddleHostCredential.credential,
        disclose: buildDisclosureList(huddleHostReq.requirements[0]),
        nonce: huddleHostReq.challenge.nonce,
        audience: huddleHostReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const huddleCreated = await postJson<{ decision: string; sessionId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/hangout/create_session`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          presentation: huddleCreatePresentation,
          nonce: huddleHostReq.challenge.nonce,
          audience: huddleHostReq.challenge.audience
        }
      );
      assert.equal(huddleCreated.decision, "ALLOW");
      const huddleJoinReq = await ensureRequirements(
        "sync.hangout.join_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.hangout.join_session", { spaceId: createdSpace.spaceId }))
      );
      const trustedPresenceCredential = await issueCredentialFor({
        subjectDid: trustedActor.did,
        vct: "cuncta.presence.mode_access",
        claims: {
          mode_access: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const huddleJoinPresentation = await buildPresentation({
        sdJwt: trustedPresenceCredential.credential,
        disclose: buildDisclosureList(huddleJoinReq.requirements[0]),
        nonce: huddleJoinReq.challenge.nonce,
        audience: huddleJoinReq.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      const huddleJoined = await postJson<{ decision: string; participant_count: number }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/hangout/join_session`,
        {
          subjectDid: trustedActor.did,
          sessionId: huddleCreated.sessionId,
          spaceId: createdSpace.spaceId,
          presentation: huddleJoinPresentation,
          nonce: huddleJoinReq.challenge.nonce,
          audience: huddleJoinReq.challenge.audience
        }
      );
      assert.equal(huddleJoined.decision, "ALLOW");
      assert.ok(huddleJoined.participant_count >= 2);
      await runSocialPhase(
        "banter hangout + status",
        "hangout chat thread and scoped status",
        async () => {
          const hangoutThreadCreateReq = await ensureRequirements(
            "banter.thread.create",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("banter.thread.create", { spaceId: createdSpace.spaceId }))
          );
          const hangoutThreadCreatePresentation = await buildPresentation({
            sdJwt: challengeMemberCredential.credential,
            disclose: buildDisclosureList(hangoutThreadCreateReq.requirements[0]),
            nonce: hangoutThreadCreateReq.challenge.nonce,
            audience: hangoutThreadCreateReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const hangoutThread = await postJson<{ decision: string; threadId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/banter/threads`,
            {
              subjectDid: socialHolderDid,
              kind: "hangout_chat",
              hangoutSessionId: huddleCreated.sessionId,
              presentation: hangoutThreadCreatePresentation,
              nonce: hangoutThreadCreateReq.challenge.nonce,
              audience: hangoutThreadCreateReq.challenge.audience
            }
          );
          assert.equal(hangoutThread.decision, "ALLOW");
          const hangoutReadReq = await ensureRequirements(
            "banter.thread.read",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("banter.thread.read", { spaceId: createdSpace.spaceId }))
          );
          const hangoutReadPresentation = await buildPresentation({
            sdJwt: challengeMemberCredential.credential,
            disclose: buildDisclosureList(hangoutReadReq.requirements[0]),
            nonce: hangoutReadReq.challenge.nonce,
            audience: hangoutReadReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const hangoutPermission = await postJson<{
            decision: string;
            permissionToken: string;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/banter/threads/${encodeURIComponent(hangoutThread.threadId)}/permission`,
            {
              subjectDid: socialHolderDid,
              presentation: hangoutReadPresentation,
              nonce: hangoutReadReq.challenge.nonce,
              audience: hangoutReadReq.challenge.audience
            }
          );
          assert.equal(hangoutPermission.decision, "ALLOW");
          const hangoutSendReq = await ensureRequirements(
            "banter.message.send",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("banter.message.send", { spaceId: createdSpace.spaceId }))
          );
          const hangoutSendPresentation = await buildPresentation({
            sdJwt: challengeMemberCredential.credential,
            disclose: buildDisclosureList(hangoutSendReq.requirements[0]),
            nonce: hangoutSendReq.challenge.nonce,
            audience: hangoutSendReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const hangoutSend = await postJson<{ decision: string; messageId: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/banter/threads/${encodeURIComponent(hangoutThread.threadId)}/send`,
            {
              subjectDid: socialHolderDid,
              bodyText: "Hangout banter, join now.",
              permissionToken: hangoutPermission.permissionToken,
              presentation: hangoutSendPresentation,
              nonce: hangoutSendReq.challenge.nonce,
              audience: hangoutSendReq.challenge.audience
            }
          );
          assert.equal(hangoutSend.decision, "ALLOW");
          const statusReq = await ensureRequirements(
            "banter.status.set",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("banter.status.set", { spaceId: createdSpace.spaceId }))
          );
          const statusPresentation = await buildPresentation({
            sdJwt: trustedPresenceCredential.credential,
            disclose: buildDisclosureList(statusReq.requirements[0]),
            nonce: statusReq.challenge.nonce,
            audience: statusReq.challenge.audience,
            holderJwk: trustedActor.keys.publicJwk,
            holderKey: trustedActor.keys.cryptoKey
          });
          const setStatus = await postJson<{ decision: string }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/status`,
            {
              subjectDid: trustedActor.did,
              mode: "active",
              statusText: "In Hangout",
              presentation: statusPresentation,
              nonce: statusReq.challenge.nonce,
              audience: statusReq.challenge.audience
            }
          );
          assert.equal(setStatus.decision, "ALLOW");
          const status = await requestJson<{
            counts: { quiet: number; active: number; immersive: number };
            you?: { status_text?: string };
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/status?viewerDid=${encodeURIComponent(trustedActor.did)}`
          );
          assert.ok(status.counts.active >= 1);
          assert.equal(status.you?.status_text, "In Hangout");
        }
      );
      await runSocialPhase(
        "pulse overlay (live hangout + prefs)",
        "GET+POST pulse endpoints respect cards and category preferences",
        async () => {
          const pulseWithHangout = await requestJson<{
            cards?: Array<{ type?: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/pulse?subjectDid=${encodeURIComponent(
              socialHolderDid
            )}`
          );
          const liveTypes = new Set((pulseWithHangout.cards ?? []).map((entry) => entry.type));
          assert.equal(liveTypes.has("hangout_live"), true);
          assert.equal(liveTypes.has("streak_risk"), false);
          const pulsePrefReq = await ensureRequirements(
            "presence.ping",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("presence.ping", { spaceId: createdSpace.spaceId }))
          );
          const pulsePrefPresentation = await buildPresentation({
            sdJwt: presenceCredential.credential,
            disclose: buildDisclosureList(pulsePrefReq.requirements[0]),
            nonce: pulsePrefReq.challenge.nonce,
            audience: pulsePrefReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const prefUpdate = await postJson<{
            preferences?: { notifyHangouts?: boolean };
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/pulse/preferences`,
            {
              subjectDid: socialHolderDid,
              notifyHangouts: false,
              presentation: pulsePrefPresentation,
              nonce: pulsePrefReq.challenge.nonce,
              audience: pulsePrefReq.challenge.audience
            }
          );
          assert.equal(prefUpdate.preferences?.notifyHangouts, false);
          const pulseAfterPref = await requestJson<{
            cards?: Array<{ type?: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/pulse?subjectDid=${encodeURIComponent(
              socialHolderDid
            )}`
          );
          const prefTypes = new Set((pulseAfterPref.cards ?? []).map((entry) => entry.type));
          assert.equal(prefTypes.has("hangout_live"), false);
        }
      );
      const huddleEndReq = await ensureRequirements(
        "sync.hangout.end_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.hangout.end_session", { spaceId: createdSpace.spaceId }))
      );
      const huddleEndPresentation = await buildPresentation({
        sdJwt: huddleHostCredential.credential,
        disclose: buildDisclosureList(huddleEndReq.requirements[0]),
        nonce: huddleEndReq.challenge.nonce,
        audience: huddleEndReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const huddleEnded = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/hangout/end_session`,
        {
          subjectDid: socialHolderDid,
          sessionId: huddleCreated.sessionId,
          spaceId: createdSpace.spaceId,
          reasonCode: "host_done",
          presentation: huddleEndPresentation,
          nonce: huddleEndReq.challenge.nonce,
          audience: huddleEndReq.challenge.audience
        }
      );
      assert.equal(huddleEnded.decision, "ALLOW");

      const scrollHostReq = await ensureRequirements(
        "sync.scroll.create_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.scroll.create_session", { spaceId: createdSpace.spaceId }))
      );
      const scrollHostCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.sync.scroll_host",
        claims: {
          scroll_host: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const scrollCreatePresentation = await buildPresentation({
        sdJwt: scrollHostCredential.credential,
        disclose: buildDisclosureList(scrollHostReq.requirements[0]),
        nonce: scrollHostReq.challenge.nonce,
        audience: scrollHostReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const scrollCreated = await postJson<{ decision: string; sessionId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/create_session`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          presentation: scrollCreatePresentation,
          nonce: scrollHostReq.challenge.nonce,
          audience: scrollHostReq.challenge.audience
        }
      );
      assert.equal(scrollCreated.decision, "ALLOW");

      const scrollJoinReq = await ensureRequirements(
        "sync.scroll.join_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.scroll.join_session", { spaceId: createdSpace.spaceId }))
      );
      const scrollJoinPresentation = await buildPresentation({
        sdJwt: trustedPresenceCredential.credential,
        disclose: buildDisclosureList(scrollJoinReq.requirements[0]),
        nonce: scrollJoinReq.challenge.nonce,
        audience: scrollJoinReq.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      const scrollJoin = await postJson<{ decision: string; permissionToken: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/join_session`,
        {
          subjectDid: trustedActor.did,
          sessionId: scrollCreated.sessionId,
          spaceId: createdSpace.spaceId,
          presentation: scrollJoinPresentation,
          nonce: scrollJoinReq.challenge.nonce,
          audience: scrollJoinReq.challenge.audience
        }
      );
      assert.equal(scrollJoin.decision, "ALLOW");
      assert.ok(scrollJoin.permissionToken);
      const scrollEvent = await postJson<{ decision: string; eventId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/sync_event`,
        {
          sessionId: scrollCreated.sessionId,
          permissionToken: scrollJoin.permissionToken,
          eventType: "SCROLL_SYNC",
          payload: { scrollY: 420, ts: Date.now() }
        }
      );
      assert.equal(scrollEvent.decision, "ALLOW");
      const persistedScrollEvent = await db("sync_session_events")
        .where({ event_id: scrollEvent.eventId, session_id: scrollCreated.sessionId })
        .first();
      assert.ok(persistedScrollEvent);
      const scrollEndReq = await ensureRequirements(
        "sync.scroll.end_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.scroll.end_session", { spaceId: createdSpace.spaceId }))
      );
      const scrollEndPresentation = await buildPresentation({
        sdJwt: scrollHostCredential.credential,
        disclose: buildDisclosureList(scrollEndReq.requirements[0]),
        nonce: scrollEndReq.challenge.nonce,
        audience: scrollEndReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const scrollEnd = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/end_session`,
        {
          subjectDid: socialHolderDid,
          sessionId: scrollCreated.sessionId,
          spaceId: createdSpace.spaceId,
          presentation: scrollEndPresentation,
          nonce: scrollEndReq.challenge.nonce,
          audience: scrollEndReq.challenge.audience
        }
      );
      assert.equal(scrollEnd.decision, "ALLOW");

      const listenHostReq = await ensureRequirements(
        "sync.listen.create_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.listen.create_session", { spaceId: createdSpace.spaceId }))
      );
      const listenHostCredential = await issueCredentialFor({
        subjectDid: socialHolderDid,
        vct: "cuncta.sync.listen_host",
        claims: {
          listen_host: true,
          domain: `space:${createdSpace.spaceId}`,
          space_id: createdSpace.spaceId,
          as_of: new Date().toISOString()
        }
      });
      const listenCreatePresentation = await buildPresentation({
        sdJwt: listenHostCredential.credential,
        disclose: buildDisclosureList(listenHostReq.requirements[0]),
        nonce: listenHostReq.challenge.nonce,
        audience: listenHostReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const listenCreated = await postJson<{ decision: string; sessionId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/listen/create_session`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          presentation: listenCreatePresentation,
          nonce: listenHostReq.challenge.nonce,
          audience: listenHostReq.challenge.audience
        }
      );
      assert.equal(listenCreated.decision, "ALLOW");
      const listenJoinReq = await ensureRequirements(
        "sync.listen.join_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.listen.join_session", { spaceId: createdSpace.spaceId }))
      );
      const listenJoinPresentation = await buildPresentation({
        sdJwt: trustedPresenceCredential.credential,
        disclose: buildDisclosureList(listenJoinReq.requirements[0]),
        nonce: listenJoinReq.challenge.nonce,
        audience: listenJoinReq.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      const listenJoin = await postJson<{ decision: string; permissionToken: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/listen/join_session`,
        {
          subjectDid: trustedActor.did,
          sessionId: listenCreated.sessionId,
          spaceId: createdSpace.spaceId,
          presentation: listenJoinPresentation,
          nonce: listenJoinReq.challenge.nonce,
          audience: listenJoinReq.challenge.audience
        }
      );
      assert.equal(listenJoin.decision, "ALLOW");
      const listenControl = await postJson<{ decision: string; eventId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/listen/broadcast_control`,
        {
          sessionId: listenCreated.sessionId,
          permissionToken: listenJoin.permissionToken,
          eventType: "LISTEN_STATE",
          payload: { playing: true, cursorMs: 1234, trackId: "test-track" }
        }
      );
      assert.equal(listenControl.decision, "ALLOW");
      const listenEndReq = await ensureRequirements(
        "sync.listen.end_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.listen.end_session", { spaceId: createdSpace.spaceId }))
      );
      const listenEndPresentation = await buildPresentation({
        sdJwt: listenHostCredential.credential,
        disclose: buildDisclosureList(listenEndReq.requirements[0]),
        nonce: listenEndReq.challenge.nonce,
        audience: listenEndReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const listenEnd = await postJson<{ decision: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/listen/end_session`,
        {
          subjectDid: socialHolderDid,
          sessionId: listenCreated.sessionId,
          spaceId: createdSpace.spaceId,
          presentation: listenEndPresentation,
          nonce: listenEndReq.challenge.nonce,
          audience: listenEndReq.challenge.audience
        }
      );
      assert.equal(listenEnd.decision, "ALLOW");

      const eraseProbeCreateReq = await ensureRequirements(
        "sync.scroll.create_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.scroll.create_session", { spaceId: createdSpace.spaceId }))
      );
      const eraseProbeCreatePresentation = await buildPresentation({
        sdJwt: scrollHostCredential.credential,
        disclose: buildDisclosureList(eraseProbeCreateReq.requirements[0]),
        nonce: eraseProbeCreateReq.challenge.nonce,
        audience: eraseProbeCreateReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      const eraseProbeSession = await postJson<{ decision: string; sessionId: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/create_session`,
        {
          subjectDid: socialHolderDid,
          spaceId: createdSpace.spaceId,
          presentation: eraseProbeCreatePresentation,
          nonce: eraseProbeCreateReq.challenge.nonce,
          audience: eraseProbeCreateReq.challenge.audience
        }
      );
      assert.equal(eraseProbeSession.decision, "ALLOW");
      const eraseProbeJoinReq = await ensureRequirements(
        "sync.scroll.join_session",
        await requestJson<{
          challenge: { nonce: string; audience: string };
          requirements: Array<{
            vct: string;
            disclosures?: string[];
            predicates?: Array<{ path: string; op: string; value?: unknown }>;
          }>;
        }>(socialRequirementsUrl("sync.scroll.join_session", { spaceId: createdSpace.spaceId }))
      );
      const eraseProbeJoinPresentation = await buildPresentation({
        sdJwt: trustedPresenceCredential.credential,
        disclose: buildDisclosureList(eraseProbeJoinReq.requirements[0]),
        nonce: eraseProbeJoinReq.challenge.nonce,
        audience: eraseProbeJoinReq.challenge.audience,
        holderJwk: trustedActor.keys.publicJwk,
        holderKey: trustedActor.keys.cryptoKey
      });
      const eraseProbeJoin = await postJson<{ decision: string; permissionToken: string }>(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/join_session`,
        {
          subjectDid: trustedActor.did,
          sessionId: eraseProbeSession.sessionId,
          spaceId: createdSpace.spaceId,
          presentation: eraseProbeJoinPresentation,
          nonce: eraseProbeJoinReq.challenge.nonce,
          audience: eraseProbeJoinReq.challenge.audience
        }
      );
      assert.equal(eraseProbeJoin.decision, "ALLOW");

      const trustedPrivacyRequest = await postJson<{
        requestId: string;
        nonce: string;
        audience: string;
      }>(`${ISSUER_SERVICE_BASE_URL}/v1/privacy/request`, { did: trustedActor.did });
      const trustedNowSeconds = Math.floor(Date.now() / 1000);
      const trustedDsrKbJwt = await new SignJWT({
        aud: trustedPrivacyRequest.audience,
        nonce: trustedPrivacyRequest.nonce,
        iat: trustedNowSeconds,
        exp: trustedNowSeconds + 120,
        cnf: { jwk: trustedActor.keys.publicJwk }
      })
        .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
        .sign(trustedActor.keys.cryptoKey);
      const trustedPrivacyConfirm = await postJson<{ dsrToken: string }>(
        `${ISSUER_SERVICE_BASE_URL}/v1/privacy/confirm`,
        {
          requestId: trustedPrivacyRequest.requestId,
          nonce: trustedPrivacyRequest.nonce,
          kbJwt: trustedDsrKbJwt
        }
      );
      const trustedRestrict = await postJson<{ nextToken?: string }>(
        `${ISSUER_SERVICE_BASE_URL}/v1/privacy/restrict`,
        { reason: `sync-restrict-${testRunId}` },
        { Authorization: `Bearer ${trustedPrivacyConfirm.dsrToken}` }
      );
      const restrictedJoinAttempt = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/join_session`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            subjectDid: trustedActor.did,
            sessionId: eraseProbeSession.sessionId,
            spaceId: createdSpace.spaceId,
            presentation: eraseProbeJoinPresentation,
            nonce: eraseProbeJoinReq.challenge.nonce,
            audience: eraseProbeJoinReq.challenge.audience
          })
        }
      );
      assert.equal(restrictedJoinAttempt.status, 403);
      const restrictedPresencePing = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/presence/ping`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            subjectDid: trustedActor.did,
            mode: "active",
            presentation: presencePingPresentation,
            nonce: presencePingReq.challenge.nonce,
            audience: presencePingReq.challenge.audience
          })
        }
      );
      assert.equal(restrictedPresencePing.status, 403);
      const restrictedPulse = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/pulse?subjectDid=${encodeURIComponent(
          trustedActor.did
        )}`,
        { headers: gatewayHeaders() }
      );
      assert.equal(restrictedPulse.status, 200);

      const trustedErase = await postJson<{ status: string }>(
        `${ISSUER_SERVICE_BASE_URL}/v1/privacy/erase`,
        { mode: "unlink" },
        { Authorization: `Bearer ${trustedRestrict.nextToken ?? trustedPrivacyConfirm.dsrToken}` }
      );
      assert.equal(trustedErase.status.toLowerCase(), "erased");

      const erasedJoinAttempt = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/join_session`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            subjectDid: trustedActor.did,
            sessionId: eraseProbeSession.sessionId,
            spaceId: createdSpace.spaceId,
            presentation: eraseProbeJoinPresentation,
            nonce: eraseProbeJoinReq.challenge.nonce,
            audience: eraseProbeJoinReq.challenge.audience
          })
        }
      );
      assert.equal(erasedJoinAttempt.status, 403);
      const erasedPulse = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/pulse?subjectDid=${encodeURIComponent(
          trustedActor.did
        )}`,
        { headers: gatewayHeaders() }
      );
      assert.ok([200, 403].includes(erasedPulse.status));
      if (erasedPulse.status === 200) {
        const payload = (await erasedPulse.json()) as { cards?: unknown[] };
        assert.equal((payload.cards ?? []).length, 0);
      }

      const erasedEventAttempt = await fetch(
        `${APP_GATEWAY_BASE_URL}/v1/social/sync/scroll/sync_event`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            sessionId: eraseProbeSession.sessionId,
            permissionToken: eraseProbeJoin.permissionToken,
            eventType: "SCROLL_SYNC",
            payload: { scrollY: 777 }
          })
        }
      );
      assert.equal(erasedEventAttempt.status, 403);

      const erasedParticipantRow = await db("sync_session_participants")
        .where({
          session_id: eraseProbeSession.sessionId,
          subject_did_hash: trustedActorHash
        })
        .first();
      assert.ok(erasedParticipantRow?.left_at);

      const socialPrivacyConfirm = await runSocialPhase(
        "DSR restrict",
        "POST /v1/privacy/request + /confirm",
        async () => {
          const socialPrivacyRequest = await postJson<{
            requestId: string;
            nonce: string;
            audience: string;
          }>(`${ISSUER_SERVICE_BASE_URL}/v1/privacy/request`, { did: socialHolderDid });
          const nowSeconds = Math.floor(Date.now() / 1000);
          const socialDsrKbJwt = await new SignJWT({
            aud: socialPrivacyRequest.audience,
            nonce: socialPrivacyRequest.nonce,
            iat: nowSeconds,
            exp: nowSeconds + 120,
            cnf: { jwk: socialHolderKeys.publicJwk }
          })
            .setProtectedHeader({ alg: "EdDSA", typ: "kb+jwt" })
            .sign(socialHolderKeys.cryptoKey);
          return postJson<{ dsrToken: string }>(`${ISSUER_SERVICE_BASE_URL}/v1/privacy/confirm`, {
            requestId: socialPrivacyRequest.requestId,
            nonce: socialPrivacyRequest.nonce,
            kbJwt: socialDsrKbJwt
          });
        }
      );
      const socialRestrict = await runSocialPhase(
        "DSR restrict",
        "POST /v1/privacy/restrict",
        async () =>
          postJson<{ nextToken?: string }>(
            `${ISSUER_SERVICE_BASE_URL}/v1/privacy/restrict`,
            { reason: `social-restrict-${testRunId}` },
            { Authorization: `Bearer ${socialPrivacyConfirm.dsrToken}` }
          )
      );

      const socialPostAfterRestrictReqRaw = await requestJson<{
        challenge: { nonce: string; audience: string };
        requirements: Array<{
          vct: string;
          disclosures?: string[];
          predicates?: Array<{ path: string; op: string; value?: unknown }>;
        }>;
      }>(socialRequirementsUrl("social.post.create"));
      const socialPostAfterRestrictReq = await ensureRequirements(
        "social.post.create",
        socialPostAfterRestrictReqRaw
      );
      const socialPostAfterRestrictPresentation = await buildPresentation({
        sdJwt: socialBaseCredential.credential,
        disclose: buildDisclosureList(socialPostAfterRestrictReq.requirements[0]),
        nonce: socialPostAfterRestrictReq.challenge.nonce,
        audience: socialPostAfterRestrictReq.challenge.audience,
        holderJwk: socialHolderKeys.publicJwk,
        holderKey: socialHolderKeys.cryptoKey
      });
      await runSocialPhase(
        "post denied",
        "POST /v1/social/post returns 403 after restrict",
        async () => {
          const deniedAfterRestrict = await fetch(`${APP_GATEWAY_BASE_URL}/v1/social/post`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              subjectDid: socialHolderDid,
              content: "This should be denied after restrict.",
              visibility: "public",
              presentation: socialPostAfterRestrictPresentation,
              nonce: socialPostAfterRestrictReq.challenge.nonce,
              audience: socialPostAfterRestrictReq.challenge.audience
            })
          });
          assert.equal(deniedAfterRestrict.status, 403);
          const deniedFollowAfterRestrict = await fetch(
            `${APP_GATEWAY_BASE_URL}/v1/social/follow`,
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                subjectDid: socialHolderDid,
                followeeDid: holderDid,
                presentation: socialPostAfterRestrictPresentation,
                nonce: socialPostAfterRestrictReq.challenge.nonce,
                audience: socialPostAfterRestrictReq.challenge.audience
              })
            }
          );
          assert.equal(deniedFollowAfterRestrict.status, 403);
          const deniedSpacePostAfterRestrict = await fetch(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/post`,
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                subjectDid: socialHolderDid,
                spaceId: createdSpace.spaceId,
                content: "Space write should be denied after restrict.",
                presentation: spacePosterCredential.presentation,
                nonce: spacePosterCredential.requirements.challenge.nonce,
                audience: spacePosterCredential.requirements.challenge.audience
              })
            }
          );
          assert.equal(deniedSpacePostAfterRestrict.status, 403);
          const emojiAfterRestrictReq = await ensureRequirements(
            "media.emoji.pack.create",
            await requestJson<{
              challenge: { nonce: string; audience: string };
              requirements: Array<{
                vct: string;
                disclosures?: string[];
                predicates?: Array<{ path: string; op: string; value?: unknown }>;
              }>;
            }>(socialRequirementsUrl("media.emoji.pack.create"))
          );
          const emojiAfterRestrictPresentation = await buildPresentation({
            sdJwt: emojiCreatorCredential.credential,
            disclose: buildDisclosureList(emojiAfterRestrictReq.requirements[0]),
            nonce: emojiAfterRestrictReq.challenge.nonce,
            audience: emojiAfterRestrictReq.challenge.audience,
            holderJwk: socialHolderKeys.publicJwk,
            holderKey: socialHolderKeys.cryptoKey
          });
          const deniedEmojiAfterRestrict = await fetch(
            `${APP_GATEWAY_BASE_URL}/v1/social/media/emoji/pack/create`,
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                subjectDid: socialHolderDid,
                spaceId: createdSpace.spaceId,
                visibility: "private",
                presentation: emojiAfterRestrictPresentation,
                nonce: emojiAfterRestrictReq.challenge.nonce,
                audience: emojiAfterRestrictReq.challenge.audience
              })
            }
          );
          assert.equal(deniedEmojiAfterRestrict.status, 403);
        }
      );

      await runSocialPhase("DSR erase", "POST /v1/privacy/erase unlink", async () =>
        postJson(
          `${ISSUER_SERVICE_BASE_URL}/v1/privacy/erase`,
          { mode: "unlink" },
          {
            Authorization: `Bearer ${socialRestrict.nextToken ?? socialPrivacyConfirm.dsrToken}`
          }
        )
      );

      await runSocialPhase(
        "feed hidden / deny writes",
        "social feed excludes erased post and social writes remain denied",
        async () => {
          await waitForSocialDbRow(
            "feed hidden / deny writes",
            "social_feed.excludes_erased_post",
            async () => {
              const feed = await requestJson<{ posts: Array<{ post_id: string }> }>(
                `${APP_GATEWAY_BASE_URL}/v1/social/feed?limit=20`
              );
              return feed.posts.some((post) => post.post_id === postAllowed.postId) ? null : feed;
            },
            180_000,
            3000
          );
          const deniedAfterErase = await fetch(`${APP_GATEWAY_BASE_URL}/v1/social/post`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              subjectDid: socialHolderDid,
              content: "Denied after erase.",
              visibility: "public",
              presentation: socialPostAfterRestrictPresentation,
              nonce: socialPostAfterRestrictReq.challenge.nonce,
              audience: socialPostAfterRestrictReq.challenge.audience
            })
          });
          assert.equal(deniedAfterErase.status, 403);
          const spaceFeedAfterErase = await requestJson<{
            posts: Array<{ space_post_id: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/space/feed?spaceId=${encodeURIComponent(createdSpace.spaceId)}&limit=20`
          );
          assert.equal(
            spaceFeedAfterErase.posts.some(
              (post) => post.space_post_id === spacePostForErase.spacePostId
            ),
            false
          );
          const leaderboardAfterErase = await requestJson<{
            top_contributors: Array<{ identity?: { displayName?: string; anonymous?: boolean } }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/spaces/${encodeURIComponent(createdSpace.spaceId)}/leaderboard?window=7d`
          );
          assert.equal(
            leaderboardAfterErase.top_contributors.some(
              (entry) => entry.identity?.displayName === "social-holder"
            ),
            false
          );
          const emojiPacksAfterErase = await db("media_emoji_packs")
            .where({ owner_subject_hash: socialSubjectHash })
            .whereNotNull("published_at");
          assert.equal(emojiPacksAfterErase.length, 0);
          const presenceAfterErase = await requestJson<{
            states?: Array<{ subject_hash: string }>;
          }>(
            `${APP_GATEWAY_BASE_URL}/v1/social/presence/state?spaceId=${encodeURIComponent(createdSpace.spaceId)}`
          );
          assert.equal(
            (presenceAfterErase.states ?? []).some(
              (entry) => entry.subject_hash === socialSubjectHash
            ),
            false
          );
          const socialRawDidInTables = await db("social_action_log")
            .where("subject_did_hash", "like", "did:%")
            .count<{ count: string }>("id as count")
            .first()
            .catch(() => ({ count: "0" }));
          assert.equal(Number(socialRawDidInTables?.count ?? 0), 0, "raw DID must not be stored");
          const socialFunnel = await requestJson<{
            funnel: Record<
              string,
              { attempts: number; allowed: number; denied: number; completed: number }
            >;
          }>(`${APP_GATEWAY_BASE_URL}/v1/social/funnel`);
          assert.ok((socialFunnel.funnel.post?.attempts ?? 0) >= 2);
          assert.ok((socialFunnel.funnel.post?.allowed ?? 0) >= 1);
          assert.ok((socialFunnel.funnel.post?.completed ?? 0) >= 1);
        }
      );
    }

    console.log("Proof artifacts: healthz + metrics + DB counts");
    await emitHealthz("did-service", `${DID_SERVICE_BASE_URL}/healthz`);
    await emitHealthz("issuer-service", `${ISSUER_SERVICE_BASE_URL}/healthz`);
    await emitHealthz("verifier-service", `${VERIFIER_SERVICE_BASE_URL}/healthz`);
    await emitHealthz("policy-service", `${POLICY_SERVICE_BASE_URL}/healthz`);
    if (SOCIAL_MODE) {
      await emitHealthz("social-service", `${SOCIAL_SERVICE_BASE_URL}/healthz`);
    }
    if (GATEWAY_MODE || SOCIAL_MODE) {
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
    if (SOCIAL_MODE) {
      await emitMetricsExcerpt("social-service", `${SOCIAL_SERVICE_BASE_URL}/metrics`);
    }
    if (GATEWAY_MODE || SOCIAL_MODE) {
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
    if (services.social) {
      await stopService(services.social, "social-service");
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
      ...(SOCIAL_MODE ? [SOCIAL_SERVICE_PORT] : []),
      ...(GATEWAY_MODE || SOCIAL_MODE ? [APP_GATEWAY_PORT] : [])
    ];
    // Only enforce port closure for processes the harness started itself. If the user already has
    // services running locally (common during iteration), we shouldn't fail the test run during
    // cleanup and mask the real failure.
    const startedPorts: number[] = [];
    if (services.did) startedPorts.push(DID_SERVICE_PORT);
    if (services.issuer) startedPorts.push(ISSUER_SERVICE_PORT);
    if (services.verifier) startedPorts.push(VERIFIER_SERVICE_PORT);
    if (services.policy) startedPorts.push(POLICY_SERVICE_PORT);
    if (services.social) startedPorts.push(SOCIAL_SERVICE_PORT);
    if (services.gateway) startedPorts.push(APP_GATEWAY_PORT);
    await sleep(2000);
    await assertPortsClosed(startedPorts);
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
