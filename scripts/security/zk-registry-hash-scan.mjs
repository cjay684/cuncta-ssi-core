import path from "node:path";
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

const repoRoot = process.cwd();
const statementsDir = path.join(repoRoot, "packages", "zk-registry", "statements");

const sha256Hex = async (absolutePath) => {
  const bytes = await readFile(absolutePath);
  return createHash("sha256").update(bytes).digest("hex");
};

const main = async () => {
  const indexRaw = await readFile(path.join(statementsDir, "index.json"), "utf8");
  const files = JSON.parse(indexRaw);
  if (!Array.isArray(files) || files.length === 0) {
    throw new Error("zk_registry_index_invalid");
  }

  const failures = [];
  for (const rel of files.map(String)) {
    const defPath = path.join(statementsDir, rel);
    const defRaw = await readFile(defPath, "utf8");
    const def = JSON.parse(defRaw);
    const isStub =
      def?.deprecated === true ||
      def?.proving_key_ref?.sha256_hex === "0".repeat(64) ||
      def?.verifying_key_ref?.sha256_hex === "0".repeat(64);
    if (isStub) continue;

    for (const key of ["proving_key_ref", "verifying_key_ref", "wasm_ref"]) {
      const ref = def?.[key];
      if (!ref) continue;
      const abs = path.join(repoRoot, String(ref.path ?? ""));
      const expected = String(ref.sha256_hex ?? "");
      const actual = await sha256Hex(abs).catch(() => "");
      if (!actual || actual !== expected) {
        failures.push({
          statement_id: def.statement_id,
          ref: key,
          path: ref.path,
          expected,
          actual
        });
      }
    }
  }

  if (failures.length) {
    console.error("zk_registry_hash_scan_failed");
    for (const f of failures) {
      console.error(
        `${f.statement_id}:${f.ref} path=${f.path} expected=${String(f.expected).slice(0, 12)} actual=${String(f.actual).slice(0, 12)}`
      );
    }
    process.exit(1);
  }
  console.log("zk_registry_hash_scan_ok");
};

main().catch((err) => {
  console.error(`zk_registry_hash_scan_error: ${err instanceof Error ? err.message : "unknown"}`);
  process.exit(2);
});
