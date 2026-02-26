import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const isTextFile = (file) =>
  file.endsWith(".ts") ||
  file.endsWith(".js") ||
  file.endsWith(".mjs") ||
  file.endsWith(".md") ||
  file.endsWith(".json") ||
  file.endsWith(".yml") ||
  file.endsWith(".yaml");

const walk = async (dir) => {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "dist") continue;
      out.push(...(await walk(p)));
    } else {
      out.push(p);
    }
  }
  return out;
};

const rel = (abs) => path.relative(repoRoot, abs).replaceAll("\\", "/");

const fail = (failures) => {
  if (!failures.length) return;
  console.error("[aura-guardrails-scan] FAIL");
  for (const f of failures) {
    console.error(`- ${f.kind}: ${f.file}${f.detail ? ` (${f.detail})` : ""}`);
  }
  process.exit(1);
};

const main = async () => {
  const failures = [];

  // Guardrail 1: no wildcard domains in seeded rules.
  const migrationsRoot = path.join(repoRoot, "packages", "db", "migrations");
  const migrationFiles = (await walk(migrationsRoot)).filter((f) => isTextFile(f));
  for (const file of migrationFiles) {
    const r = rel(file);
    if (r.endsWith("packages/db/migrations/043_aura_capability_scoping.ts")) {
      // This migration intentionally references "*" only to remediate legacy wildcard rows.
      continue;
    }
    const content = await readFile(file, "utf8").catch(() => "");
    if (content.includes('domain: "*"') || content.includes('domain:"*"')) {
      failures.push({ kind: "wildcard_domain_seeded", file: r, detail: 'domain: "*"' });
    }
  }

  // Guardrail 2: known aura seed migrations must include purpose text.
  const requiredPurposeFiles = [
    "packages/db/migrations/008_obligations_aura.ts",
    "packages/db/migrations/020_seed_social_vertical.ts",
    "packages/db/migrations/021_social_mvp_refine.ts",
    "packages/db/migrations/022_social_v01_alignment.ts",
    "packages/db/migrations/023_social_spaces_v02.ts"
  ];
  for (const fileRel of requiredPurposeFiles) {
    const abs = path.join(repoRoot, fileRel);
    const content = await readFile(abs, "utf8").catch(() => "");
    if (!content.includes("purpose:")) {
      failures.push({ kind: "missing_purpose_in_seed_migration", file: fileRel });
    }
  }

  // Guardrail 3: prevent unauthenticated "raw aura state" endpoints from being introduced.
  // (Heuristic scan: forbid routes named /v1/aura/state or /v1/aura/raw).
  const routeRoots = [
    path.join(repoRoot, "apps", "issuer-service", "src", "routes"),
    path.join(repoRoot, "apps", "social-service", "src", "routes"),
    path.join(repoRoot, "apps", "app-gateway", "src", "routes")
  ];
  const routeFiles = (await Promise.all(routeRoots.map((r) => walk(r)))).flat().filter((f) => isTextFile(f));
  for (const file of routeFiles) {
    const r = rel(file);
    const content = await readFile(file, "utf8").catch(() => "");
    for (const forbidden of ['"/v1/aura/state"', '"/v1/aura/raw"', "'/v1/aura/state'", "'/v1/aura/raw'"]) {
      if (content.includes(forbidden)) {
        failures.push({ kind: "raw_aura_endpoint_forbidden", file: r, detail: forbidden });
      }
    }
  }

  fail(failures);
  console.log("[aura-guardrails-scan] OK");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

