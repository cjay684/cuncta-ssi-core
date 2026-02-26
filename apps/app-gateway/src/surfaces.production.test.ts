import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";
import { readFile, readdir } from "node:fs/promises";
import { mkdtempSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { canonicalizeJson, type SurfaceRegistry } from "@cuncta/shared";

const repoRootFromThisFile = () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "..");
};

const b64url = (input: string | Buffer) => Buffer.from(input).toString("base64url");

const writeSignedSurfaceBundle = (registry: SurfaceRegistry) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const publicKeyEnv = b64url(JSON.stringify({ ...publicJwk, alg: "EdDSA", kid: "surface-registry-test-1" }));

  const protectedHeader = { alg: "EdDSA", typ: "surface-registry+json", kid: "surface-registry-test-1" };
  const protectedB64 = b64url(JSON.stringify(protectedHeader));

  const payloadText = canonicalizeJson(registry);
  const payloadB64 = b64url(payloadText);

  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "utf8");
  const signatureBytes = cryptoSign(null, signingInput, privateKey);
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");

  const bundle = {
    registry,
    signature: {
      protected: protectedB64,
      payload: payloadB64,
      signature: signatureB64
    }
  };

  const dir = mkdtempSync(path.join(os.tmpdir(), "gateway-surfaces-prod-"));
  const bundlePath = path.join(dir, "surfaces.registry.bundle.json");
  writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), "utf8");
  return { bundlePath, publicKeyEnv };
};

const readDocsSurfaces = async () => {
  const repoRoot = repoRootFromThisFile();
  const docPath = path.join(repoRoot, "docs", "surfaces.md");
  return await readFile(docPath, "utf8");
};

const extractGatewaySurfaceRoutesFromDocs = (markdown: string) => {
  // Pull every backticked "METHOD /path" line under "### app-gateway".
  const lines = markdown.split("\n");
  const routes: Array<{ method: string; path: string }> = [];
  let inGateway = false;
  for (const line of lines) {
    if (line.startsWith("### ")) {
      inGateway = line.trim() === "### app-gateway";
      continue;
    }
    if (!inGateway) continue;
    const match = line.match(/`(GET|POST|PUT|DELETE|PATCH)\s+([^`]+)`/);
    if (!match) continue;
    routes.push({ method: match[1]!, path: match[2]!.trim() });
  }
  return routes;
};

const readSurfaceRegistry = async () => {
  const repoRoot = repoRootFromThisFile();
  const registryPath = path.join(repoRoot, "docs", "surfaces.registry.json");
  const raw = await readFile(registryPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (
    !parsed ||
    typeof parsed !== "object" ||
    (parsed as any).schemaVersion !== 1 ||
    !Array.isArray((parsed as any).services)
  ) {
    throw new Error("invalid_surface_registry");
  }
  return parsed as SurfaceRegistry;
};

const registryRoutesForService = (
  registry: Awaited<ReturnType<typeof readSurfaceRegistry>>,
  serviceId: string
) => {
  const svc = registry.services.find((s) => s?.id === serviceId);
  const routes = Array.isArray(svc?.routes) ? svc!.routes : [];
  return routes
    .map((r) => ({
      method: String(r.method ?? "").toUpperCase(),
      path: String(r.path ?? "").trim(),
      surface: String(r.surface ?? "").trim(),
      disabledStatus: typeof (r as any).disabledStatus === "number" ? (r as any).disabledStatus : undefined,
      probe: (r as any).probe as undefined | { path?: string; headers?: Record<string, string>; body?: unknown }
    }))
    .filter((r) => Boolean(r.method && r.path.startsWith("/")));
};

const walkRoutesDir = async (dir: string): Promise<string[]> => {
  const out: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) continue;
    if (entry.isFile() && entry.name.endsWith(".ts")) out.push(full);
  }
  return out;
};

const extractPublicProtocolRoutesFromCode = async (input: { routesDir: string }) => {
  const files = await walkRoutesDir(input.routesDir);
  const allowPrefixes = [
    "/oid4vp",
    "/oid4vci",
    "/v1/onboard",
    "/v1/dids/resolve",
    "/healthz",
    "/metrics",
    "/.well-known/jwks.json"
  ];
  const found = new Set<string>();

  const re = /\bapp\.(get|post|put|delete|patch)\(\s*["']([^"']+)["']/g;
  for (const file of files) {
    const content = await readFile(file, "utf8");
    for (const match of content.matchAll(re)) {
      const method = String(match[1] ?? "").toUpperCase();
      const p = String(match[2] ?? "");
      if (!allowPrefixes.some((prefix) => p.startsWith(prefix))) continue;
      found.add(`${method} ${p}`);
    }
  }
  return found;
};

const run = async (name: string, fn: () => Promise<void>) => {
  try {
    await fn();
    // eslint-disable-next-line no-console
    console.log(`ok - ${name}`);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(`not ok - ${name}`);
    // eslint-disable-next-line no-console
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

const isFastifyDefault404 = (response: { statusCode: number; body: string; json: () => any }) => {
  if (response.statusCode !== 404) return false;
  try {
    const body = response.json() as any;
    return (
      body &&
      typeof body.message === "string" &&
      body.message.startsWith("Route ") &&
      body.error === "Not Found" &&
      body.statusCode === 404
    );
  } catch {
    return response.body.includes("Route ") && response.body.includes("Not Found");
  }
};

const assertNoSurfaceLeak = (input: { body: string; disallowRouteStrings: string[]; context: string }) => {
  const body = String(input.body ?? "");
  const lower = body.toLowerCase();
  const bannedNeedles = ["bearer", "scope", "admin"];
  for (const needle of bannedNeedles) {
    assert.equal(
      lower.includes(needle),
      false,
      `surface enforcement response leaked "${needle}" (${input.context})`
    );
  }
  for (const routeStr of input.disallowRouteStrings) {
    if (!routeStr) continue;
    assert.equal(
      lower.includes(routeStr.toLowerCase()),
      false,
      `surface enforcement response leaked route string "${routeStr}" (${input.context})`
    );
  }
};

await run("production surface docs cover gateway protocol routes", async () => {
  const markdown = await readDocsSurfaces();
  const docRoutes = extractGatewaySurfaceRoutesFromDocs(markdown).map((r) => `${r.method} ${r.path}`);
  assert.ok(docRoutes.length > 0, "expected docs/surfaces.md to list app-gateway routes");
  const docSet = new Set(docRoutes);

  const repoRoot = repoRootFromThisFile();
  const routesDir = path.join(repoRoot, "apps", "app-gateway", "src", "routes");
  const codeRoutes = await extractPublicProtocolRoutesFromCode({ routesDir });

  for (const route of codeRoutes) {
    assert.ok(docSet.has(route), `docs/surfaces.md missing app-gateway route: ${route}`);
  }

  // Also fail if docs list a route that no longer exists in code (avoid drift).
  for (const route of docSet) {
    // Only enforce for the protocol surface we scan from code.
    const pathPart = route.split(" ").slice(1).join(" ");
    const allowPrefixes = [
      "/oid4vp",
      "/oid4vci",
      "/v1/onboard",
      "/v1/dids/resolve",
      "/healthz",
      "/metrics",
      "/.well-known/jwks.json"
    ];
    if (!allowPrefixes.some((prefix) => pathPart.startsWith(prefix))) continue;
    assert.ok(codeRoutes.has(route), `docs/surfaces.md lists non-existent app-gateway route: ${route}`);
  }
});

const setupProdPublicEnv = () => {
  // Important: this file uses dynamic imports after env is set.
  process.env.NODE_ENV = "production";
  process.env.PUBLIC_SERVICE = "true";
  process.env.TRUST_PROXY = "true";
  process.env.DEV_MODE = "false";
  process.env.BACKUP_RESTORE_MODE = "false";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.SERVICE_BIND_ADDRESS = "127.0.0.1";

  // Strict secret format is enforced in production; use hex length >= 64.
  const secretHex = "0123456789abcdef".repeat(4);
  process.env.SERVICE_JWT_SECRET = secretHex;
  process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";

  process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "pepper-test-123456";
  process.env.USER_PAYS_HANDOFF_SECRET =
    process.env.USER_PAYS_HANDOFF_SECRET ?? "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  // Base URLs are required by config parsing; they do not need to be reachable for these tests.
  process.env.DID_SERVICE_BASE_URL = process.env.DID_SERVICE_BASE_URL ?? "http://127.0.0.1:3001";
  process.env.ISSUER_SERVICE_BASE_URL = process.env.ISSUER_SERVICE_BASE_URL ?? "http://127.0.0.1:3002";
  process.env.VERIFIER_SERVICE_BASE_URL = process.env.VERIFIER_SERVICE_BASE_URL ?? "http://127.0.0.1:3003";
  process.env.SOCIAL_SERVICE_BASE_URL = process.env.SOCIAL_SERVICE_BASE_URL ?? "http://127.0.0.1:3005";

  // Ensure the JWKS proxy route is registered (it will return 503 if upstream isn't reachable).
  process.env.APP_GATEWAY_PUBLIC_BASE_URL =
    process.env.APP_GATEWAY_PUBLIC_BASE_URL ?? "https://gateway.example";
  process.env.GATEWAY_SIGN_OID4VP_REQUEST = process.env.GATEWAY_SIGN_OID4VP_REQUEST ?? "true";

  // DB is not required for these tests; routes are probed so they fail before DB usage.
  process.env.DATABASE_URL =
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@127.0.0.1:5432/cuncta_ssi";
};

await run("runtime public posture fails closed (gateway)", async () => {
  setupProdPublicEnv();
  const registry = await readSurfaceRegistry();
  const routes = registryRoutesForService(registry, "app-gateway");
  assert.ok(routes.length > 0, "expected surface registry to include app-gateway routes");

  const { bundlePath, publicKeyEnv } = writeSignedSurfaceBundle(registry);
  process.env.SURFACE_REGISTRY_PATH = bundlePath;
  process.env.SURFACE_REGISTRY_PUBLIC_KEY = publicKeyEnv;

  const { buildServer } = await import("./server.js");
  const { config } = await import("./config.js");

  const app = buildServer({ configOverride: { ...config } });
  try {
    for (const entry of routes) {
      const probePath = entry.probe?.path ?? "";
      assert.ok(probePath.startsWith("/"), `missing probe.path for registry entry: ${entry.method} ${entry.path}`);

      const response = await (app as any).inject({
        method: entry.method as any,
        url: probePath,
        headers: entry.probe?.headers,
        payload: entry.probe?.body as any
      });

      if (entry.surface === "public") {
        // Public routes may legitimately return 404 for "resource not found"; what we must avoid is a missing handler.
        assert.equal(
          isFastifyDefault404(response as any),
          false,
          `public route should be registered (not Fastify default 404): ${entry.method} ${probePath}`
        );
      } else if (entry.surface === "internal" || entry.surface === "admin") {
        assert.ok(
          (response as any).statusCode === 401 || (response as any).statusCode === 403,
          `expected 401/403 for ${entry.surface} route without token: ${entry.method} ${probePath} (got ${response.statusCode})`
        );
        assertNoSurfaceLeak({
          body: (response as any).body,
          disallowRouteStrings: [entry.path, probePath],
          context: `${entry.method} ${probePath} (${entry.surface})`
        });
      } else if (entry.surface === "dev_test_only") {
        const expected = entry.disabledStatus === 410 ? 410 : 404;
        assert.equal(
          (response as any).statusCode,
          expected,
          `expected ${expected} for dev/test-only route in public production: ${entry.method} ${probePath} (got ${response.statusCode})`
        );
        assertNoSurfaceLeak({
          body: (response as any).body,
          disallowRouteStrings: [entry.path, probePath],
          context: `${entry.method} ${probePath} (dev_test_only)`
        });
      } else {
        throw new Error(`unknown surface kind: ${entry.surface}`);
      }
    }

    const unknown = await (app as any).inject({ method: "GET", url: "/__unknown__/route" });
    assert.equal((unknown as any).statusCode, 404, "unknown route should return 404");
  } finally {
    await app.close();
  }
});

