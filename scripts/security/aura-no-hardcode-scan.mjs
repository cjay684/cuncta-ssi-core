import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const isTextFile = (file) =>
  file.endsWith(".ts") ||
  file.endsWith(".js") ||
  file.endsWith(".mjs") ||
  file.endsWith(".json") ||
  file.endsWith(".yml") ||
  file.endsWith(".yaml");

const isTestFile = (fileRel) =>
  fileRel.endsWith(".test.ts") ||
  fileRel.endsWith(".test.js") ||
  fileRel.includes("/src/test/") ||
  fileRel.includes("/src/tests/") ||
  fileRel.includes("/test/") ||
  fileRel.includes("/tests/");

const walk = async (dir) => {
  const out = [];
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const entry of entries) {
    const p = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules" || entry.name === "dist" || entry.name.startsWith(".")) continue;
      out.push(...(await walk(p)));
    } else {
      out.push(p);
    }
  }
  return out;
};

const rel = (abs) => path.relative(repoRoot, abs).replaceAll("\\", "/");

const extractSeededAuraIds = async () => {
  const migrationsRoot = path.join(repoRoot, "packages", "db", "migrations");
  const migrationFiles = (await walk(migrationsRoot)).filter((f) => isTextFile(f));
  const ruleIds = new Set();
  const outputVcts = new Set();
  const reRuleId = /rule_id\s*:\s*["']([^"']+)["']/g;
  const reOutput = /output_vct\s*:\s*["']([^"']+)["']/g;
  for (const file of migrationFiles) {
    const content = await readFile(file, "utf8").catch(() => "");
    for (const match of content.matchAll(reRuleId)) {
      const id = String(match[1] ?? "").trim();
      if (id) ruleIds.add(id);
    }
    for (const match of content.matchAll(reOutput)) {
      const vct = String(match[1] ?? "").trim();
      if (vct) outputVcts.add(vct);
    }
  }
  const auraConfigIds = new Set(Array.from(outputVcts).map((vct) => `aura:${vct}`));
  return { ruleIds, auraConfigIds };
};

const fail = (failures) => {
  if (!failures.length) return;
  console.error("[aura-no-hardcode-scan] FAIL");
  for (const f of failures) {
    console.error(`- ${f.kind}: ${f.file} (${f.detail})`);
  }
  process.exit(1);
};

const main = async () => {
  const { ruleIds, auraConfigIds } = await extractSeededAuraIds();
  const forbiddenStrings = [
    ...Array.from(ruleIds).map((s) => ({ kind: "seeded_rule_id_literal", value: s })),
    ...Array.from(auraConfigIds).map((s) => ({ kind: "seeded_aura_config_id_literal", value: s }))
  ];

  const roots = [
    path.join(repoRoot, "apps", "issuer-service", "src"),
    path.join(repoRoot, "apps", "social-service", "src"),
    path.join(repoRoot, "apps", "verifier-service", "src"),
    path.join(repoRoot, "apps", "policy-service", "src"),
    path.join(repoRoot, "apps", "did-service", "src"),
    path.join(repoRoot, "apps", "app-gateway", "src"),
    path.join(repoRoot, "packages", "shared", "src")
  ];
  const files = (await Promise.all(roots.map((r) => walk(r)))).flat().filter((f) => isTextFile(f));

  const failures = [];
  for (const file of files) {
    const fileRel = rel(file);
    if (isTestFile(fileRel)) continue;
    const content = await readFile(file, "utf8").catch(() => "");
    for (const { kind, value } of forbiddenStrings) {
      if (!value) continue;
      if (content.includes(value)) {
        failures.push({ kind, file: fileRel, detail: value });
      }
    }
  }

  fail(failures);
  console.log("[aura-no-hardcode-scan] OK");
};

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

