import { strict as assert } from "node:assert";
import { mkdtemp, readFile, writeFile, copyFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = process.cwd();

const REGISTRY_PATH = path.join(repoRoot, "docs", "surfaces.registry.json");
const BUNDLE_PATH = path.join(repoRoot, "docs", "surfaces.registry.bundle.json");

// Matches the CI workflow default; can be overridden by env.
const DEV_FALLBACK_PUBLIC_JWK_B64URL =
  "eyJjcnYiOiJFZDI1NTE5IiwieCI6ImNGTWxNek91bjJmSkEybXJROE8wNXhsLUI1SjlnTlQ5RE1HVEZGVkQxZVkiLCJrdHkiOiJPS1AiLCJhbGciOiJFZERTQSIsImtpZCI6InN1cmZhY2UtcmVnaXN0cnktZGV2LTEifQ";

const run = async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "surface-registry-drift-test-"));
  const tmpRegistry = path.join(dir, "surfaces.registry.json");
  const tmpBundle = path.join(dir, "surfaces.registry.bundle.json");

  // Copy the committed bundle, but mutate the registry without re-signing.
  await copyFile(BUNDLE_PATH, tmpBundle);

  const registryRaw = await readFile(REGISTRY_PATH, "utf8");
  const registry = JSON.parse(registryRaw);
  assert.ok(registry && typeof registry === "object", "expected registry JSON");
  assert.ok(Array.isArray(registry.services) && registry.services.length > 0, "expected services array");

  // Mutate a single property to ensure the canonical payload changes.
  const svc0 = registry.services[0];
  assert.ok(svc0 && typeof svc0 === "object" && Array.isArray(svc0.routes) && svc0.routes.length > 0);
  const r0 = svc0.routes[0];
  assert.ok(r0 && typeof r0 === "object");
  r0.path = String(r0.path) + "-drift-test";

  await writeFile(tmpRegistry, JSON.stringify(registry, null, 2) + "\n", "utf8");

  const publicKey = String(process.env.SURFACE_REGISTRY_PUBLIC_KEY ?? "").trim() || DEV_FALLBACK_PUBLIC_JWK_B64URL;
  const signScript = path.join(repoRoot, "scripts", "security", "sign-surface-registry.mjs");

  const res = spawnSync(process.execPath, [signScript, "--verify", "--registry-path", tmpRegistry, "--bundle-path", tmpBundle], {
    env: { ...process.env, SURFACE_REGISTRY_PUBLIC_KEY: publicKey },
    encoding: "utf8"
  });

  assert.notEqual(res.status, 0, "expected verify to fail when registry drifts without re-sign");
  const combined = `${res.stdout ?? ""}\n${res.stderr ?? ""}`;
  assert.ok(
    combined.includes("surface_registry_bundle_registry_mismatch") || combined.includes("surface_registry_integrity_failed"),
    `unexpected failure output: ${combined}`
  );
};

run().catch((error) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

