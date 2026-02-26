import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const isTextFile = (p) =>
  [".ts", ".tsx", ".js", ".mjs", ".cjs"].includes(path.extname(p).toLowerCase());

const shouldSkipDir = (name) =>
  name === "node_modules" ||
  name === "dist" ||
  name === "coverage" ||
  name === ".git" ||
  name === ".tmp-wallet" ||
  name === ".next";

const walk = async (dir) => {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    if (e.isDirectory()) {
      if (shouldSkipDir(e.name)) continue;
      out.push(...(await walk(path.join(dir, e.name))));
    } else if (e.isFile()) {
      out.push(path.join(dir, e.name));
    }
  }
  return out;
};

const rel = (p) => path.relative(repoRoot, p).replaceAll("\\", "/");
const statementIdPathAllowlist = new Set([
  // Baseline policy seed is expected to reference the canonical statement id.
  "apps/policy-service/src/bootstrap.ts"
]);

const main = async () => {
  // This gate is about *core ZK engine usage paths* (policy/gateway/issuer/wallet/verifier),
  // not about circuit packages, migrations, docs, or artifact builders.
  const scanRoots = [
    "apps/app-gateway/src",
    "apps/issuer-service/src",
    "apps/policy-service/src",
    "apps/verifier-service/src",
    "apps/wallet-cli/src",
    "packages/zk-registry/src"
  ].map((p) => path.join(repoRoot, p));

  const all = (await Promise.all(scanRoots.map((r) => walk(r)))).flat();
  const failures = [];

  // Gate 1: prevent statement-id hardcoding in core code.
  // Allowlist: tests.
  const forbiddenStatementId = "age_gte_v1";
  for (const file of all) {
    const r = rel(file);
    if (!isTextFile(file)) continue;
    if (r.includes(".test.")) continue;
    if (statementIdPathAllowlist.has(r)) continue;
    const content = await readFile(file, "utf8").catch(() => "");
    if (!content) continue;
    if (content.includes(forbiddenStatementId)) {
      failures.push({
        kind: "hardcoded_statement_id",
        file: r,
        match: forbiddenStatementId
      });
    }
  }

  // Gate 2: verifier core must not import circuit-specific packages.
  const verifierRoots = ["apps/verifier-service/src/core", "apps/verifier-service/src/zk"];
  for (const rootRel of verifierRoots) {
    const rootAbs = path.join(repoRoot, rootRel);
    const files = (await walk(rootAbs)).filter((f) => isTextFile(f));
    for (const file of files) {
      const content = await readFile(file, "utf8").catch(() => "");
      if (!content) continue;
      if (content.includes("@cuncta/zk-age-snark") || content.includes("packages/zk-age-snark")) {
        failures.push({
          kind: "verifier_imports_circuit_specific",
          file: rel(file),
          match: "@cuncta/zk-age-snark"
        });
      }
    }
  }

  if (failures.length) {
    console.error("[zk-no-hardcode-scan] FAIL");
    for (const f of failures) {
      console.error(`- ${f.kind}: ${f.file} (match: ${f.match})`);
    }
    process.exit(1);
  }

  console.log("[zk-no-hardcode-scan] OK");
};

main().catch((err) => {
  console.error("[zk-no-hardcode-scan] ERROR", err instanceof Error ? err.message : err);
  process.exit(2);
});

