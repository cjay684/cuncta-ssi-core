import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { fileURLToPath } from "node:url";
import { canonicalizeJson, type SurfaceRegistry } from "@cuncta/shared";

const b64url = (input: string | Buffer) => Buffer.from(input).toString("base64url");

const repoRootFromThisFile = () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "..", "..");
};

const readSurfaceRegistry = (): SurfaceRegistry => {
  const registryPath = path.join(repoRootFromThisFile(), "docs", "surfaces.registry.json");
  const raw = readFileSync(registryPath, "utf8");
  const parsed = JSON.parse(raw) as unknown;
  if (!parsed || typeof parsed !== "object") {
    throw new Error("invalid_surface_registry");
  }
  return parsed as SurfaceRegistry;
};

const makeSignedBundleFile = (
  registry: SurfaceRegistry,
  mutate?: (r: SurfaceRegistry) => SurfaceRegistry
) => {
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

  const effectiveRegistry = mutate ? mutate(registry) : registry;
  const payloadText = canonicalizeJson(effectiveRegistry);
  const payloadB64 = b64url(payloadText);

  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "utf8");
  const signatureBytes = cryptoSign(null, signingInput, privateKey);
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");

  const bundle = {
    registry: effectiveRegistry,
    signature: {
      protected: protectedB64,
      payload: payloadB64,
      signature: signatureB64
    }
  };

  const dir = mkdtempSync(path.join(os.tmpdir(), "gateway-surface-registry-"));
  const bundlePath = path.join(dir, "surfaces.registry.bundle.json");
  writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), "utf8");
  return { bundlePath, publicKeyEnv };
};

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
    process.env.USER_PAYS_HANDOFF_SECRET ??
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

  // Base URLs are required by config parsing; they do not need to be reachable for these tests.
  process.env.DID_SERVICE_BASE_URL = process.env.DID_SERVICE_BASE_URL ?? "http://127.0.0.1:3001";
  process.env.ISSUER_SERVICE_BASE_URL =
    process.env.ISSUER_SERVICE_BASE_URL ?? "http://127.0.0.1:3002";
  process.env.VERIFIER_SERVICE_BASE_URL =
    process.env.VERIFIER_SERVICE_BASE_URL ?? "http://127.0.0.1:3003";
  // Ensure the JWKS proxy route is registered (it will return 503 if upstream isn't reachable).
  process.env.APP_GATEWAY_PUBLIC_BASE_URL =
    process.env.APP_GATEWAY_PUBLIC_BASE_URL ?? "https://gateway.example";
  process.env.GATEWAY_SIGN_OID4VP_REQUEST = process.env.GATEWAY_SIGN_OID4VP_REQUEST ?? "true";

  // DB is not required for these tests; routes are probed so they fail before DB usage.
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

await run("production startup loads valid signed surface bundle (gateway)", async () => {
  setupProdPublicEnv();
  const registry = readSurfaceRegistry();
  const { bundlePath, publicKeyEnv } = makeSignedBundleFile(registry);
  process.env.SURFACE_REGISTRY_PATH = bundlePath;
  process.env.SURFACE_REGISTRY_PUBLIC_KEY = publicKeyEnv;

  const { buildServer } = await import("./server.js");
  const { config } = await import("./config.js");
  const app = buildServer({ configOverride: { ...config } });
  try {
    await app.ready();
  } finally {
    await app.close();
  }
});

await run("production startup fails closed on tampered surface bundle (gateway)", async () => {
  setupProdPublicEnv();
  const registry = readSurfaceRegistry();

  // Sign a correct payload, then tamper the registry object without updating signature.
  const { bundlePath, publicKeyEnv } = (() => {
    const signed = makeSignedBundleFile(registry);
    const raw = readFileSync(signed.bundlePath, "utf8");
    const parsed = JSON.parse(raw) as {
      registry?: { services?: unknown };
      [k: string]: unknown;
    };
    if (!parsed.registry || typeof parsed.registry !== "object") {
      throw new Error("invalid_surface_bundle");
    }
    parsed.registry.services = Array.isArray(parsed.registry.services)
      ? parsed.registry.services.slice(0, 1)
      : [];
    writeFileSync(signed.bundlePath, JSON.stringify(parsed, null, 2), "utf8");
    return signed;
  })();

  process.env.SURFACE_REGISTRY_PATH = bundlePath;
  process.env.SURFACE_REGISTRY_PUBLIC_KEY = publicKeyEnv;

  const { buildServer } = await import("./server.js");
  const { config } = await import("./config.js");
  const app = buildServer({ configOverride: { ...config } });
  try {
    await assert.rejects(
      async () => app.ready(),
      (e: unknown) => {
        return e instanceof Error && e.message === "surface_registry_integrity_failed";
      }
    );
  } finally {
    await app.close().catch(() => undefined);
  }
});
