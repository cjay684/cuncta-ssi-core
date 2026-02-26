import { spawnSync } from "node:child_process";

// Regression gate: ensure we don't accidentally persist ZK proof blobs.
// Design intent: proofs are transient and must not be inserted/updated into Postgres.

const repoRoot = process.cwd();

// Heuristic: flag any insert/update payloads that mention zk_proof(s).
const pattern = String.raw`(\.insert|\.(update|patch)|knex\().*(zk_proof|zk_proofs)`;

const args = [
  "--json",
  "--no-heading",
  "--line-number",
  "--hidden",
  "--glob",
  "apps/**/src/**/*.{ts,js,mjs,cjs}",
  "--glob",
  "!apps/**/src/**/*.test.*",
  pattern,
  repoRoot
];

const result = spawnSync("rg", args, { encoding: "utf8", shell: process.platform === "win32" });
if (result.error) {
  console.error(`zk_proof_db_scan_failed_to_run_rg: ${result.error.message}`);
  process.exit(2);
}

const findings = [];
for (const line of (result.stdout ?? "").split("\n")) {
  if (!line.trim()) continue;
  let parsed;
  try {
    parsed = JSON.parse(line);
  } catch {
    continue;
  }
  if (parsed.type !== "match") continue;
  findings.push({
    path: parsed.data?.path?.text ?? "",
    line: parsed.data?.line_number,
    text: (parsed.data?.lines?.text ?? "").trimEnd()
  });
}

if (findings.length) {
  console.error("zk_proof_db_scan_failed");
  for (const f of findings.slice(0, 50)) {
    console.error(`${f.path}:${f.line}: ${f.text}`);
  }
  if (findings.length > 50) {
    console.error(`... (${findings.length - 50} more)`);
  }
  process.exit(1);
}

console.log("zk_proof_db_scan_ok");

