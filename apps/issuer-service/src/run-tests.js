import path from "node:path";
import { runServiceTests } from "../../../scripts/test-runner.mjs";

const repoRoot = path.resolve(process.cwd());
const srcRoot = path.join(repoRoot, "src");

const requiresDb = (file) => {
  const normalized = file.replaceAll("\\", "/");
  return (
    normalized.includes("/aura/") ||
    normalized.includes("/issuer/") ||
    normalized.includes("/privacy/") ||
    normalized.includes("/reputation/") ||
    normalized.includes("/hedera/") ||
    normalized.includes("anchorWorker") ||
    normalized.includes("cleanupWorker") ||
    normalized.includes("pseudonymizer") ||
    normalized.includes("restoreValidation") ||
    normalized.includes("dev.disabled-production")
  );
};

const requiresIntegration = (file) => {
  const normalized = file.replaceAll("\\", "/");
  return (
    normalized.endsWith("/aura/auraClaim.test.ts") ||
    normalized.endsWith("/issuer/catalog-driven.test.ts") ||
    normalized.endsWith("/issuer/issuance.subject.test.ts") ||
    normalized.endsWith("/issuer/issuance.concurrent.test.ts") ||
    normalized.endsWith("/issuer/keyRing.rotation.test.ts") ||
    normalized.endsWith("/reputation/engine.test.ts")
  );
};

const run = async () => {
  await runServiceTests({
    srcRoot,
    workerUrl: new URL("./test-worker.js", import.meta.url),
    requiresDb,
    requiresIntegration
  });
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
