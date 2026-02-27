import { strict as assert } from "node:assert";
import path from "node:path";
import os from "node:os";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { mkdtempSync, writeFileSync } from "node:fs";
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
  const publicKeyEnv = b64url(
    JSON.stringify({ ...publicJwk, alg: "EdDSA", kid: "surface-registry-test-1" })
  );

  const protectedHeader = {
    alg: "EdDSA",
    typ: "surface-registry+json",
    kid: "surface-registry-test-1"
  };
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

  const dir = mkdtempSync(path.join(os.tmpdir(), "issuer-surfaces-prod-"));
  const bundlePath = path.join(dir, "surfaces.registry.bundle.json");
  writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), "utf8");
  return { bundlePath, publicKeyEnv };
};

const readSurfaceRegistry = async () => {
  const repoRoot = repoRootFromThisFile();
  const registryPath = path.join(repoRoot, "docs", "surfaces.registry.json");
  const raw = await readFile(registryPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  const candidate = parsed as Partial<SurfaceRegistry> | null;
  if (
    !candidate ||
    typeof candidate !== "object" ||
    candidate.schemaVersion !== 1 ||
    !Array.isArray(candidate.services)
  ) {
    throw new Error("invalid_surface_registry");
  }
  return candidate as SurfaceRegistry;
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
      disabledStatus:
        typeof (r as Record<string, unknown>).disabledStatus === "number"
          ? ((r as Record<string, unknown>).disabledStatus as number)
          : undefined,
      probe: ((r as Record<string, unknown>).probe ?? undefined) as
        | undefined
        | { path?: string; headers?: Record<string, string>; body?: unknown }
    }))
    .filter((r) => Boolean(r.method && r.path.startsWith("/")));
};

const isFastifyDefault404 = (response: {
  statusCode: number;
  body: string;
  json: () => unknown;
}) => {
  if (response.statusCode !== 404) return false;
  try {
    const body = response.json() as { message?: unknown; error?: unknown; statusCode?: unknown };
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

const assertNoSurfaceLeak = (input: {
  body: string;
  disallowRouteStrings: string[];
  context: string;
}) => {
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

const setupProdPublicEnv = () => {
  process.env.NODE_ENV = "production";
  process.env.PUBLIC_SERVICE = "true";
  process.env.TRUST_PROXY = "true";
  process.env.SERVICE_BIND_ADDRESS = "127.0.0.1";
  process.env.DEV_MODE = "false";
  process.env.BACKUP_RESTORE_MODE = "false";
  process.env.HEDERA_NETWORK = "testnet";
  process.env.ALLOW_MAINNET = "false";

  process.env.ISSUER_BASE_URL = "http://issuer.test";
  process.env.DID_SERVICE_BASE_URL = "http://did.test";
  process.env.ISSUER_DID = "did:example:issuer";

  // Minimal JWKs to satisfy config invariants. These values are not used to mint real credentials in this test.
  process.env.ISSUER_JWK =
    process.env.ISSUER_JWK ??
    JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "test",
      d: "test",
      alg: "EdDSA",
      kid: "issuer-1"
    });
  process.env.OID4VCI_TOKEN_SIGNING_JWK =
    process.env.OID4VCI_TOKEN_SIGNING_JWK ??
    JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "test",
      d: "test",
      alg: "EdDSA",
      kid: "oid4vci-token-1"
    });
  process.env.OID4VCI_TOKEN_SIGNING_BOOTSTRAP = "false";

  process.env.POLICY_SIGNING_JWK =
    process.env.POLICY_SIGNING_JWK ??
    JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "test",
      d: "test",
      alg: "EdDSA",
      kid: "policy-1"
    });

  process.env.PSEUDONYMIZER_PEPPER = process.env.PSEUDONYMIZER_PEPPER ?? "pepper-test-123456";

  // Strict secret format is enforced in production; use hex length >= 64.
  const secretHex = "0123456789abcdef".repeat(4);
  process.env.SERVICE_JWT_SECRET = secretHex;
  process.env.SERVICE_JWT_SECRET_ISSUER = secretHex;
  process.env.SERVICE_JWT_AUDIENCE = "cuncta-internal";

  process.env.DATABASE_URL =
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@127.0.0.1:5432/cuncta_ssi";
};

const run = async (name: string, fn: () => Promise<void>) => {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

await run("runtime public posture fails closed (issuer-service)", async () => {
  setupProdPublicEnv();
  // issuer-service enforces production invariants via DB-backed checks in onReady.
  // For local/unit runs without a DB, skip rather than flaking/hanging.
  const requireDb = process.env.RUN_DB_TESTS === "1";
  const dbAvailable = await (async () => {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) return false;
    let db: { raw: (sql: string) => Promise<unknown>; destroy: () => Promise<unknown> } | undefined;
    try {
      const { createDb } = await import("@cuncta/db");
      db = createDb(databaseUrl);
      await Promise.race([
        db.raw("select 1"),
        new Promise((_, reject) => setTimeout(() => reject(new Error("db_probe_timeout")), 1500))
      ]);
      return true;
    } catch {
      return false;
    } finally {
      if (db) {
        await db.destroy().catch(() => undefined);
      }
    }
  })();
  if (!dbAvailable) {
    if (requireDb) {
      throw new Error("database_unavailable_but_required");
    }
    console.log(
      "skipped - runtime public posture fails closed (issuer-service) (database unavailable)"
    );
    return;
  }

  const registry = await readSurfaceRegistry();
  const routes = registryRoutesForService(registry, "issuer-service");
  assert.ok(routes.length > 0, "expected surface registry to include issuer-service routes");

  const { bundlePath, publicKeyEnv } = writeSignedSurfaceBundle(registry);
  process.env.SURFACE_REGISTRY_PATH = bundlePath;
  process.env.SURFACE_REGISTRY_PUBLIC_KEY = publicKeyEnv;

  const { buildServer } = await import("./server.js");
  const app = buildServer();
  const appForTest = app as {
    inject: (input: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      payload?: unknown;
    }) => Promise<{
      statusCode: number;
      body: string;
      json: () => unknown;
    }>;
    close: () => Promise<void>;
  };
  try {
    for (const entry of routes) {
      const probePath = entry.probe?.path ?? "";
      assert.ok(
        probePath.startsWith("/"),
        `missing probe.path for registry entry: ${entry.method} ${entry.path}`
      );

      const response = await appForTest.inject({
        method: entry.method,
        url: probePath,
        headers: entry.probe?.headers,
        payload: entry.probe?.body
      });

      if (entry.surface === "public") {
        // Public routes may legitimately return 404 for "resource not found"; what we must avoid is a missing handler.
        assert.equal(
          isFastifyDefault404(response),
          false,
          `public route should be registered (not Fastify default 404): ${entry.method} ${probePath}`
        );
      } else if (entry.surface === "internal" || entry.surface === "admin") {
        assert.ok(
          response.statusCode === 401 || response.statusCode === 403,
          `expected 401/403 for ${entry.surface} route without token: ${entry.method} ${probePath} (got ${response.statusCode})`
        );
        assertNoSurfaceLeak({
          body: response.body,
          disallowRouteStrings: [entry.path, probePath],
          context: `${entry.method} ${probePath} (${entry.surface})`
        });
      } else if (entry.surface === "dev_test_only") {
        const expected = entry.disabledStatus === 410 ? 410 : 404;
        assert.equal(
          response.statusCode,
          expected,
          `expected ${expected} for dev/test-only route in public production: ${entry.method} ${probePath} (got ${response.statusCode})`
        );
        assertNoSurfaceLeak({
          body: response.body,
          disallowRouteStrings: [entry.path, probePath],
          context: `${entry.method} ${probePath} (dev_test_only)`
        });
      } else {
        throw new Error(`unknown surface kind: ${entry.surface}`);
      }
    }

    const unknown = await appForTest.inject({ method: "GET", url: "/__unknown__/route" });
    assert.equal(unknown.statusCode, 404, "unknown route should return 404");
  } finally {
    await app.close();
  }
});
