import { strict as assert } from "node:assert";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { canonicalizeJson } from "./canonicalJson.js";
import {
  SURFACE_REGISTRY_CANON_VERSION,
  verifySurfaceRegistryBundle,
  type SurfaceRegistry
} from "./surfaceRegistry.js";

const b64url = (input: string | Buffer) => Buffer.from(input).toString("base64url");

const makeSignedBundle = (input: { registry: SurfaceRegistry; canon: number }) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" }) as Record<string, unknown>;
  const kid = "surface-registry-canon-test-1";
  const publicKeyEnv = b64url(JSON.stringify({ ...publicJwk, alg: "EdDSA", kid }));

  const protectedHeader = { alg: "EdDSA", typ: "surface-registry+json", kid, canon: input.canon };
  const protectedB64 = b64url(JSON.stringify(protectedHeader));

  const payloadText = canonicalizeJson(input.registry);
  const payloadB64 = b64url(payloadText);

  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "utf8");
  const signatureBytes = cryptoSign(null, signingInput, privateKey);
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");

  const bundle = {
    registry: input.registry,
    signature: {
      protected: protectedB64,
      payload: payloadB64,
      signature: signatureB64
    }
  };

  return { bundle, publicKeyEnv };
};

const run = async () => {
  // Intentionally build with odd key insertion order so that:
  // - canonicalizeJson() is stable
  // - JSON.stringify() differs (used by test 3 to simulate canonicalization drift)
  const svc0: SurfaceRegistry["services"][number] = {
    id: "app-gateway",
    publiclyDeployable: true,
    routes: [{ method: "GET", path: "/healthz", surface: "public", probe: { path: "/healthz" } }]
  };
  const registryWithOrder = {} as Pick<SurfaceRegistry, "services" | "schemaVersion">;
  registryWithOrder.services = [svc0];
  registryWithOrder.schemaVersion = 1;
  const registry = registryWithOrder as SurfaceRegistry;

  // 1) Valid bundle with canon=1 loads.
  {
    const { bundle, publicKeyEnv } = makeSignedBundle({
      registry,
      canon: SURFACE_REGISTRY_CANON_VERSION
    });
    const loaded = await verifySurfaceRegistryBundle({
      bundle,
      publicKeyJwkBase64url: publicKeyEnv
    });
    assert.deepEqual(loaded, registry);
  }

  // 2) Bundle with canon=2 fails when local CANON_VERSION=1.
  {
    const { bundle, publicKeyEnv } = makeSignedBundle({
      registry,
      canon: SURFACE_REGISTRY_CANON_VERSION + 1
    });
    await assert.rejects(
      async () => verifySurfaceRegistryBundle({ bundle, publicKeyJwkBase64url: publicKeyEnv }),
      (e: unknown) =>
        e instanceof Error && e.message === "surface_registry_canonicalization_version_mismatch"
    );
  }

  // 3) Changing canonicalization without bumping version must fail verification.
  // Simulated by verifying with a different canonicalizer than the signer used.
  {
    const { bundle, publicKeyEnv } = makeSignedBundle({
      registry,
      canon: SURFACE_REGISTRY_CANON_VERSION
    });
    await assert.rejects(
      async () =>
        verifySurfaceRegistryBundle({
          bundle,
          publicKeyJwkBase64url: publicKeyEnv,
          canonicalize: (v: unknown) => JSON.stringify(v) // NOT recursive key-sorted
        }),
      (e: unknown) => e instanceof Error && e.message === "surface_registry_integrity_failed"
    );
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
