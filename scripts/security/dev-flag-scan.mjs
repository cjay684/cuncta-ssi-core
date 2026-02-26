import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import path from "node:path";

const repoRoot = process.cwd();

const parseEnvExample = () => {
  const p = path.join(repoRoot, ".env.example");
  const raw = readFileSync(p, "utf8");
  const lines = raw.split("\n");
  const map = new Map();
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (!key) continue;
    map.set(key, value);
  }
  return { path: p, map };
};

const isTruthy = (raw) => {
  const v = String(raw ?? "").trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
};

const main = () => {
  const { path: envPath, map } = parseEnvExample();
  const failures = [];

  const forbiddenTrueDefaults = [
    "ALLOW_INSECURE_DEV_AUTH",
    "PUBLIC_SERVICE",
    "ALLOW_EXPERIMENTAL_ZK",
    "ISSUER_KEYS_BOOTSTRAP",
    "VERIFIER_SIGNING_BOOTSTRAP",
    "POLICY_SIGNING_BOOTSTRAP",
    "ALLOW_INSECURE_WALLET_KEYS",
    // Test-only guard; must never be enabled by default.
    "CI_TEST_MODE"
  ];
  for (const key of forbiddenTrueDefaults) {
    const raw = map.get(key);
    if (raw !== undefined && isTruthy(raw)) {
      failures.push({ kind: "forbidden_true_default", key, value: raw });
    }
  }

  // Break-glass must never be enabled by default in the example env.
  const breakGlass = map.get("BREAK_GLASS_DISABLE_STRICT");
  if (breakGlass !== undefined && isTruthy(breakGlass)) {
    failures.push({ kind: "break_glass_enabled_by_default", key: "BREAK_GLASS_DISABLE_STRICT", value: breakGlass });
  }

  // CI-only flags must not be wired into shipped artifacts (Docker images, etc).
  // This is a conservative text scan; we fail if the string appears at all.
  try {
    const dockerfiles = execSync("git ls-files \"**/Dockerfile\" \"**/Dockerfile.*\"", {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"]
    })
      .toString("utf8")
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    for (const file of dockerfiles) {
      const raw = readFileSync(path.join(repoRoot, file), "utf8");
      if (raw.includes("CI_TEST_MODE")) {
        failures.push({ kind: "ci_test_mode_referenced_in_dockerfile", key: file, value: "CI_TEST_MODE" });
      }
    }
  } catch (err) {
    // If git isn't available, don't fail the scan; the env.example checks still hold.
    // This is mostly for CI where git is always present.
  }

  if (failures.length) {
    console.error("[dev-flag-scan] FAIL");
    console.error(`env=${envPath}`);
    for (const f of failures) {
      console.error(`- ${f.kind}: ${f.key}=${f.value}`);
    }
    process.exit(1);
  }

  console.log("[dev-flag-scan] OK");
};

try {
  main();
} catch (err) {
  console.error("[dev-flag-scan] ERROR", err instanceof Error ? err.message : err);
  process.exit(2);
}

