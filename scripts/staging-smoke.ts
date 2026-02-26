import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { SignJWT } from "jose";

const textEncoder = new TextEncoder();

const truthy = (value: string | undefined) => value === "true" || value === "1" || value === "yes";

const requireEnv = (name: string) => {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`env_missing:${name}`);
  }
  return value.trim();
};

const sleepMs = async (ms: number) => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

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
    await sleepMs(Math.min(opts.intervalMs, opts.timeoutMs - (Date.now() - started)));
  }
  const diagnostic = {
    label,
    elapsedMs: Date.now() - started,
    timeoutMs: opts.timeoutMs,
    lastResponse: last.lastResponse ?? "no_response"
  };
  throw new Error(`waitFor_timeout: ${JSON.stringify(diagnostic)}`);
};

const run = (label: string, args: string[], env: Record<string, string>) => {
  const result = spawnSync("pnpm", args, {
    env: { ...process.env, ...env },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    shell: true
  });
  const out = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
  if (result.status !== 0) {
    throw new Error(`${label}_failed:exit_${result.status}\n${out}`);
  }
  return out;
};

const decodeJwtPayload = (jwtOrSdJwt: string) => {
  // SD-JWT is "jws~disclosures~..." — we only need the JWS payload.
  const token = jwtOrSdJwt.split("~")[0] ?? "";
  const parts = token.split(".");
  if (parts.length < 2) {
    throw new Error("jwt_decode_failed");
  }
  const payload = Buffer.from(parts[1]!, "base64url").toString("utf8");
  return JSON.parse(payload) as Record<string, unknown>;
};

const parseStatusFromCredential = (sdJwt: string) => {
  const payload = decodeJwtPayload(sdJwt);
  const status = payload.status as
    | { statusListCredential?: unknown; statusListIndex?: unknown }
    | undefined;
  const statusListCredential =
    typeof status?.statusListCredential === "string" ? status.statusListCredential : "";
  const statusListIndex = typeof status?.statusListIndex === "string" ? status.statusListIndex : "";
  if (!statusListCredential || !statusListIndex) {
    throw new Error("credential_status_missing");
  }
  // Expect: https://issuer.example/status-lists/<listId>
  const match = statusListCredential.match(/\/status-lists\/([^/?#]+)\b/);
  const statusListId = match?.[1] ?? "";
  if (!statusListId) {
    throw new Error("credential_status_list_id_missing");
  }
  const indexNumber = Number(statusListIndex);
  if (!Number.isInteger(indexNumber) || indexNumber < 0) {
    throw new Error("credential_status_index_invalid");
  }
  return { statusListId, statusListIndex: indexNumber };
};

const createServiceJwt = async (input: {
  secret: string;
  audience: string;
  scope: string[];
  ttlSeconds?: number;
}) => {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const ttlSeconds = input.ttlSeconds ?? 120;
  return await new SignJWT({
    aud: input.audience,
    scope: input.scope,
    iat: nowSeconds,
    exp: nowSeconds + ttlSeconds,
    iss: "app-gateway",
    sub: "app-gateway"
  })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .sign(textEncoder.encode(input.secret));
};

const postJson = async (url: string, body: unknown, headers?: Record<string, string>) => {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", ...(headers ?? {}) },
    body: JSON.stringify(body)
  });
  const text = await res.text();
  let payload: unknown = null;
  try {
    payload = text ? (JSON.parse(text) as unknown) : null;
  } catch {
    payload = text;
  }
  return { ok: res.ok, status: res.status, payload };
};

const runStagingSmoke = async () => {
  // Required staging URLs (public, not localhost).
  const APP_GATEWAY_BASE_URL = requireEnv("APP_GATEWAY_BASE_URL");
  const ISSUER_SERVICE_BASE_URL = requireEnv("ISSUER_SERVICE_BASE_URL");

  // Self-funded onboarding keys (wallet signs/pays).
  requireEnv("HEDERA_PAYER_ACCOUNT_ID");
  requireEnv("HEDERA_PAYER_PRIVATE_KEY");

  // Network selection must be config-only.
  const HEDERA_NETWORK = (process.env.HEDERA_NETWORK ?? "testnet").trim();
  const ALLOW_MAINNET = (process.env.ALLOW_MAINNET ?? "false").trim();
  if (HEDERA_NETWORK === "mainnet" && !truthy(ALLOW_MAINNET)) {
    throw new Error("mainnet_not_allowed: set ALLOW_MAINNET=true");
  }

  // What we prove.
  const action = (process.env.SMOKE_ACTION ?? "marketplace.list_item").trim();
  const vct = (process.env.SMOKE_VCT ?? "cuncta.marketplace.seller_good_standing").trim();

  // Keep CI runs isolated from developer state.
  const workspaceRoot = path.resolve(process.cwd());
  const smokeDir = path.join(workspaceRoot, ".staging-smoke");
  await fs.mkdir(smokeDir, { recursive: true });
  const walletStateFile = path.join(smokeDir, "wallet-state.json");

  const walletEnv: Record<string, string> = {
    // Consumer flows should work via gateway URLs only.
    APP_GATEWAY_BASE_URL,
    DID_SERVICE_BASE_URL: APP_GATEWAY_BASE_URL,
    ISSUER_SERVICE_BASE_URL,

    HEDERA_NETWORK,
    ALLOW_MAINNET,

    // Strict-by-default posture.
    WALLET_VERIFY_REQUEST_SIGNATURE: "true",
    BREAK_GLASS_DISABLE_STRICT: "false",

    WALLET_STATE_FILE: walletStateFile
  };

  console.log(`[smoke] using wallet state file: ${walletStateFile}`);

  console.log("[smoke] 1) DID create (self-funded via gateway)");
  run("did_create_user_pays_gateway", ["-C", "apps/wallet-cli", "did:create:user-pays-gateway"], walletEnv);

  console.log("[smoke] 2) OID4VCI acquire credential");
  run(
    "vc_acquire",
    ["-C", "apps/wallet-cli", "vc:acquire", "--", "--config-id", vct],
    walletEnv
  );

  console.log("[smoke] 3) OID4VP request -> wallet response -> ALLOW (signature verified)");
  const requestUrl = new URL("/oid4vp/request", APP_GATEWAY_BASE_URL);
  requestUrl.searchParams.set("action", action);
  const allowOut = run(
    "vp_respond_allow",
    ["-C", "apps/wallet-cli", "vp:respond", "--", "--request", requestUrl.toString(), "--credential-vct", vct],
    walletEnv
  );
  const allowPayload = JSON.parse(allowOut) as { decision?: string };
  if (allowPayload.decision !== "ALLOW") {
    throw new Error(`oid4vp_expected_allow_got:${allowPayload.decision ?? "unknown"}`);
  }

  console.log("[smoke] 4) Revoke -> verify DENY (operator action, service-auth required)");
  const SERVICE_JWT_SECRET_ISSUER = requireEnv("SERVICE_JWT_SECRET_ISSUER");
  const SERVICE_JWT_AUDIENCE_ISSUER =
    (process.env.SERVICE_JWT_AUDIENCE_ISSUER ?? "cuncta.service.issuer").trim();
  const token = await createServiceJwt({
    secret: SERVICE_JWT_SECRET_ISSUER,
    audience: SERVICE_JWT_AUDIENCE_ISSUER,
    scope: ["issuer:revoke"]
  });
  const walletState = JSON.parse(await fs.readFile(walletStateFile, "utf8")) as {
    credentials?: Array<{ vct?: string; credential?: string; sdJwt?: string }>;
  };
  const acquired = (walletState.credentials ?? []).find((c) => c.vct === vct);
  const sdJwt = (acquired?.credential ?? acquired?.sdJwt ?? "").trim();
  if (!sdJwt) {
    throw new Error("wallet_state_missing_acquired_credential");
  }
  const status = parseStatusFromCredential(sdJwt);
  const revokeRes = await postJson(
    new URL("/v1/revoke", ISSUER_SERVICE_BASE_URL).toString(),
    status,
    { Authorization: `Bearer ${token}` }
  );
  if (!revokeRes.ok) {
    throw new Error(`revoke_failed:http_${revokeRes.status}:${JSON.stringify(revokeRes.payload)}`);
  }

  // Status list caching + propagation can take a few seconds; deterministically poll until DENY.
  await waitFor(
    "revocation_visible",
    async () => {
      let denyPayload: { decision?: string; reasons?: string[] } | null = null;
      try {
        const denyOut = run(
          "vp_respond_after_revoke",
          [
            "-C",
            "apps/wallet-cli",
            "vp:respond",
            "--",
            "--request",
            requestUrl.toString(),
            "--credential-vct",
            vct
          ],
          walletEnv
        );
        denyPayload = JSON.parse(denyOut) as { decision?: string; reasons?: string[] };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const health = await fetch(new URL("/healthz", APP_GATEWAY_BASE_URL), { method: "GET" }).catch(
          () => null
        );
        return {
          done: false,
          lastResponse: {
            verifyError: message,
            healthStatus: health?.status ?? "unreachable"
          }
        };
      }
      if (denyPayload?.decision === "DENY") {
        return { done: true, lastResponse: denyPayload };
      }
      const health = await fetch(new URL("/healthz", APP_GATEWAY_BASE_URL), { method: "GET" }).catch(
        () => null
      );
      return {
        done: false,
        lastResponse: {
          decision: denyPayload?.decision ?? "unknown",
          reasons: denyPayload?.reasons ?? [],
          healthStatus: health?.status ?? "unreachable"
        }
      };
    },
    { timeoutMs: 60_000, intervalMs: 2500 }
  );

  console.log("[smoke] 5) Anchor reconcile (operator action) sees at least one VERIFIED receipt");
  const adminToken = await createServiceJwt({
    secret: SERVICE_JWT_SECRET_ISSUER,
    audience: SERVICE_JWT_AUDIENCE_ISSUER,
    scope: ["issuer:anchor_reconcile"]
  });
  await waitFor(
    "anchor_reconcile_verified",
    async () => {
      const reconcileRes = await postJson(
        new URL("/v1/admin/anchors/reconcile", ISSUER_SERVICE_BASE_URL).toString(),
        { limit: 5, force: true },
        { Authorization: `Bearer ${adminToken}` }
      );
      if (reconcileRes.ok) {
        const payload = reconcileRes.payload as any;
        const results = Array.isArray(payload?.results) ? payload.results : [];
        if (results.some((r: any) => r?.status === "VERIFIED")) {
          return { done: true, lastResponse: payload };
        }
        return { done: false, lastResponse: { status: reconcileRes.status, payload } };
      }
      return { done: false, lastResponse: { status: reconcileRes.status, payload: reconcileRes.payload } };
    },
    { timeoutMs: 2 * 60_000, intervalMs: 4000 }
  );

  console.log("staging smoke: OK");
};

runStagingSmoke().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

