import { strict as assert } from "node:assert";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { canonicalizeJson } from "./canonicalJson.js";
import {
  loadSurfaceRegistryForRuntime,
  SURFACE_REGISTRY_CANON_VERSION,
  verifySurfaceRegistryBundle,
  type SurfaceRegistry
} from "./surfaceRegistry.js";

const b64url = (input: string | Buffer) => Buffer.from(input).toString("base64url");

const makeSignedBundle = (registry: SurfaceRegistry) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const publicKeyEnv = b64url(JSON.stringify({ ...publicJwk, alg: "EdDSA", kid: "surface-registry-test-1" }));

  const protectedHeader = {
    alg: "EdDSA",
    typ: "surface-registry+json",
    kid: "surface-registry-test-1",
    canon: SURFACE_REGISTRY_CANON_VERSION
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

  return { bundle, publicKeyEnv };
};

const run = async () => {
  const registry: SurfaceRegistry = {
    schemaVersion: 1,
    services: [
      {
        id: "app-gateway",
        publiclyDeployable: true,
        routes: [{ method: "GET", path: "/healthz", surface: "public", probe: { path: "/healthz" } }]
      }
    ]
  };

  {
    const { bundle, publicKeyEnv } = makeSignedBundle(registry);
    const loaded = await verifySurfaceRegistryBundle({ bundle, publicKeyJwkBase64url: publicKeyEnv });
    assert.deepEqual(loaded, registry);
  }

  {
    const { bundle, publicKeyEnv } = makeSignedBundle(registry);
    const tampered = {
      ...bundle,
      registry: {
        ...bundle.registry,
        services: [...bundle.registry.services, { id: "issuer-service", routes: [] }]
      }
    };
    await assert.rejects(
      async () => verifySurfaceRegistryBundle({ bundle: tampered as any, publicKeyJwkBase64url: publicKeyEnv }),
      (e: unknown) => e instanceof Error && e.message === "surface_registry_integrity_failed"
    );
  }

  {
    const { bundle, publicKeyEnv } = makeSignedBundle(registry);
    const tamperedSignature = (() => {
      const first = bundle.signature.signature[0] ?? "A";
      const replacement = first === "A" ? "B" : "A";
      return `${replacement}${bundle.signature.signature.slice(1)}`;
    })();
    const invalidSig = {
      ...bundle,
      signature: {
        ...bundle.signature,
        signature: tamperedSignature
      }
    };
    await assert.rejects(
      async () => verifySurfaceRegistryBundle({ bundle: invalidSig as any, publicKeyJwkBase64url: publicKeyEnv }),
      (e: unknown) => e instanceof Error && e.message === "surface_registry_integrity_failed"
    );
  }

  {
    const { bundle, publicKeyEnv } = makeSignedBundle(registry);
    const dir = mkdtempSync(path.join(os.tmpdir(), "surface-registry-test-"));
    const bundlePath = path.join(dir, "surfaces.registry.bundle.json");
    const registryPath = path.join(dir, "surfaces.registry.json");
    writeFileSync(bundlePath, JSON.stringify(bundle, null, 2), "utf8");
    writeFileSync(registryPath, JSON.stringify(registry, null, 2), "utf8");

    const loaded = await loadSurfaceRegistryForRuntime({
      nodeEnv: "production",
      bundlePath,
      registryPath,
      publicKeyJwkBase64url: publicKeyEnv
    });
    assert.deepEqual(loaded, registry);
  }

  {
    const dir = mkdtempSync(path.join(os.tmpdir(), "surface-registry-test-"));
    const bundlePath = path.join(dir, "surfaces.registry.bundle.json");
    const registryPath = path.join(dir, "surfaces.registry.json");
    writeFileSync(bundlePath, "{}", "utf8");
    writeFileSync(registryPath, "{}", "utf8");

    await assert.rejects(
      async () =>
        loadSurfaceRegistryForRuntime({
          nodeEnv: "production",
          bundlePath,
          registryPath
          // publicKeyJwkBase64url intentionally missing
        }),
      (e: unknown) => e instanceof Error && e.message === "surface_registry_integrity_failed"
    );
  }
};

run().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

