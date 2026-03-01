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
  console.error("[capability-guardrails-scan] FAIL");
  for (const f of failures) {
    console.error(`- ${f.kind}: ${f.file}${f.detail ? ` (${f.detail})` : ""}`);
  }
  process.exit(1);
};

const main = async () => {
  const failures = [];

  // Guardrail: no wildcard domains in seeded rules.
  const migrationsRoot = path.join(repoRoot, "packages", "db", "migrations");
  const migrationFiles = (await walk(migrationsRoot)).filter((f) => isTextFile(f));
  for (const file of migrationFiles) {
    const r = rel(file);
    const content = await readFile(file, "utf8").catch(() => "");
    if (content.includes('domain: "*"') || content.includes('domain:"*"')) {
      failures.push({ kind: "wildcard_domain_seeded", file: r, detail: 'domain: "*"' });
    }
  }

  fail(failures);
  console.log("[capability-guardrails-scan] OK");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
