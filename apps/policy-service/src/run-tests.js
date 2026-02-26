import path from "node:path";
import { runServiceTests } from "../../../scripts/test-runner.mjs";

const repoRoot = path.resolve(process.cwd());
const srcRoot = path.join(repoRoot, "src");

const requiresDb = (file) => {
  const normalized = file.replaceAll("\\", "/");
  return (
    normalized.endsWith("/invariants.test.ts") ||
    normalized.endsWith("/policy/evaluate.test.ts") ||
    normalized.endsWith("/policy/capability.audit.test.ts") ||
    normalized.endsWith("/routes/requirements.test.ts") ||
    normalized.endsWith("/routes/policy.integrity.test.ts")
  );
};

const run = async () => {
  await runServiceTests({
    srcRoot,
    workerUrl: new URL("./test-worker.js", import.meta.url),
    requiresDb
  });
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
