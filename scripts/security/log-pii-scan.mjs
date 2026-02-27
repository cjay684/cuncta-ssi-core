import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";

const repoRoot = process.cwd();

const allowlistPath = path.join(repoRoot, ".pii-scan-allowlist.json");
const allowlist = existsSync(allowlistPath)
  ? JSON.parse(readFileSync(allowlistPath, "utf8"))
  : { ignorePathRegex: [], ignoreMatchRegex: [] };

const ignorePathRegex = (allowlist.ignorePathRegex ?? []).map((p) => new RegExp(String(p)));
const ignoreMatchRegex = (allowlist.ignoreMatchRegex ?? []).map((p) => new RegExp(String(p)));

const pattern =
  // Only scan log statements; this is a regression gate against accidentally logging secrets/PII.
  // We only flag *string literals* that look like secrets/PII. Object keys like `did:` are common and safe.
  String.raw`log\.(info|warn|error|debug)\(.*(("Authorization:"|'Authorization:')|("Bearer "|'Bearer ')|("did:"|'did:')|("proof\.jwt"|'proof\.jwt')|("~"|'~')|("eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"|'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'))`;

const args = [
  "--json",
  "--no-heading",
  "--line-number",
  "--hidden",
  "--glob",
  "apps/**/src/**/*.{ts,js,mjs,cjs}",
  pattern,
  repoRoot
];

const result = spawnSync("rg", args, { encoding: "utf8" });
if (result.error) {
  console.error(`pii_scan_failed_to_run_rg: ${result.error.message}`);
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
  const filePath = parsed.data?.path?.text ?? "";
  const matchText = parsed.data?.lines?.text ?? "";
  if (ignorePathRegex.some((re) => re.test(filePath))) continue;
  if (ignoreMatchRegex.some((re) => re.test(matchText))) continue;
  findings.push({
    path: filePath,
    line: parsed.data?.line_number,
    text: matchText.trimEnd()
  });
}

if (findings.length) {
  console.error("log_pii_scan_failed");
  for (const f of findings.slice(0, 50)) {
    console.error(`${f.path}:${f.line}: ${f.text}`);
  }
  if (findings.length > 50) {
    console.error(`... (${findings.length - 50} more)`);
  }
  console.error(
    "To allowlist a false positive, add regex to .pii-scan-allowlist.json (ignorePathRegex or ignoreMatchRegex)."
  );
  process.exit(1);
}

console.log("log_pii_scan_ok");
