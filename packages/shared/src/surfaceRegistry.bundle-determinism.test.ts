import { strict as assert } from "node:assert";
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { canonicalizeJson } from "./canonicalJson.js";
import { SURFACE_REGISTRY_CANON_VERSION, type SurfaceRegistry } from "./surfaceRegistry.js";

const b64url = (input: string | Buffer) => Buffer.from(input).toString("base64url");

const signCanonicalRegistry = (input: {
  registry: SurfaceRegistry;
  privateKey: KeyObject;
  kid: string;
}) => {
  const protectedHeader = {
    alg: "EdDSA",
    typ: "surface-registry+json",
    kid: input.kid,
    canon: SURFACE_REGISTRY_CANON_VERSION
  };
  const protectedB64 = b64url(JSON.stringify(protectedHeader));

  const payloadText = canonicalizeJson(input.registry);
  const payloadB64 = b64url(payloadText);

  const signingInput = Buffer.from(`${protectedB64}.${payloadB64}`, "utf8");
  const signatureBytes = cryptoSign(null, signingInput, input.privateKey);
  const signatureB64 = Buffer.from(signatureBytes).toString("base64url");

  return { protectedB64, payloadText, payloadB64, signatureB64 };
};

const run = () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const kid = "surface-registry-determinism-test-1";

  // Same semantic registry, intentionally different key insertion order.
  const registryA: SurfaceRegistry = {
    schemaVersion: 1,
    services: [
      {
        id: "app-gateway",
        publiclyDeployable: true,
        routes: [
          { method: "GET", path: "/healthz", surface: "public", probe: { path: "/healthz" } }
        ]
      }
    ]
  };

  const routeB = {} as SurfaceRegistry["services"][number]["routes"][number];
  routeB.surface = "public";
  routeB.path = "/healthz";
  routeB.method = "GET";
  routeB.probe = { path: "/healthz" };

  const svcB = {} as SurfaceRegistry["services"][number];
  svcB.routes = [routeB];
  svcB.publiclyDeployable = true;
  svcB.id = "app-gateway";

  const registryB = {} as Pick<SurfaceRegistry, "services" | "schemaVersion">;
  registryB.services = [svcB];
  registryB.schemaVersion = 1;

  const canonA = canonicalizeJson(registryA);
  const canonB = canonicalizeJson(registryB);
  assert.equal(canonA, canonB, "canonical JSON should be identical regardless of key order");

  const sigA = signCanonicalRegistry({ registry: registryA, privateKey, kid });
  const sigB = signCanonicalRegistry({ registry: registryB as SurfaceRegistry, privateKey, kid });

  assert.equal(sigA.payloadB64, sigB.payloadB64, "payload bytes must be identical");
  assert.equal(
    sigA.signatureB64,
    sigB.signatureB64,
    "Ed25519 signature must be deterministic for same signing input"
  );

  // Real registry change => canonical payload changes => signature changes.
  const registryChanged: SurfaceRegistry = {
    ...registryA,
    services: [
      {
        ...registryA.services[0]!,
        routes: [{ ...registryA.services[0]!.routes[0]!, surface: "internal" }]
      }
    ]
  };
  const sigChanged = signCanonicalRegistry({ registry: registryChanged, privateKey, kid });
  assert.notEqual(
    sigA.payloadB64,
    sigChanged.payloadB64,
    "changed registry must change canonical payload"
  );
  assert.notEqual(
    sigA.signatureB64,
    sigChanged.signatureB64,
    "changed registry must change signature"
  );
};

try {
  run();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
