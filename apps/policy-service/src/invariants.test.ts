import { strict as assert } from "node:assert";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { getDb } from "./db.js";

const repoRoot = path.resolve(process.cwd(), "../..");

const walk = async (dir: string, acc: string[] = []) => {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (
      entry.name === "node_modules" ||
      entry.name === "dist" ||
      entry.name === "build" ||
      entry.name.startsWith(".")
    ) {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, acc);
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".ts")) {
      acc.push(full);
    }
  }
  return acc;
};

const run = async () => {
  const appSrc = path.join(repoRoot, "apps");
  const pkgSrc = path.join(repoRoot, "packages");
  const files = [...(await walk(appSrc)), ...(await walk(pkgSrc))];
  const networkAllowlist = [
    path.join("apps", "app-gateway", "src", "config.ts"),
    path.join("apps", "app-gateway", "src", "server.ts"),
    path.join("apps", "app-gateway", "src", "routes", "onboard.ts"),
    path.join("apps", "did-service", "src", "config.ts"),
    path.join("apps", "did-service", "src", "hedera", "client.ts"),
    path.join("apps", "did-service", "src", "routes", "dids.ts"),
    path.join("apps", "did-service", "src", "state", "ephemeralState.ts"),
    path.join("apps", "issuer-service", "src", "config.ts"),
    path.join("apps", "issuer-service", "src", "hedera", "anchorReconciler.ts"),
    path.join("apps", "issuer-service", "src", "hedera", "anchorWorker.ts"),
    path.join("apps", "policy-service", "src", "config.ts"),
    path.join("apps", "policy-service", "src", "config.d.ts"),
    path.join("apps", "verifier-service", "src", "config.ts"),
    path.join("apps", "verifier-service", "src", "zk", "verifyZkPredicates.ts"),
    path.join("packages", "payments", "src", "index.ts"),
    path.join("packages", "hedera", "src", "index.ts")
  ];
  const ignoredPrefixes = [
    path.join("apps", "contract-e2e"),
    path.join("apps", "integration-tests"),
    path.join("apps", "mobile-wallet"),
    path.join("apps", "wallet-cli")
  ];

  for (const file of files) {
    const relative = path.relative(repoRoot, file);
    if (ignoredPrefixes.some((entry) => relative.startsWith(entry))) {
      continue;
    }
    if (file.endsWith("invariants.test.ts")) {
      continue;
    }
    const content = await readFile(file, "utf8");
    if (content.includes("mainnet") || content.includes("previewnet")) {
      const allowed = networkAllowlist.some((entry) => relative.endsWith(entry));
      if (!allowed) {
        throw new Error(`network_invariant_failed: ${file}`);
      }
    }
    const requestBodyLog = /(log\.\w+|console\.\w+)\([^)]*request\.body/;
    const requestHeadersLog = /(log\.\w+|console\.\w+)\([^)]*request\.headers/;
    if (requestBodyLog.test(content) || requestHeadersLog.test(content)) {
      throw new Error(`request_body_logging_failed: ${file}`);
    }
  }

  const migrationsDir = path.join(repoRoot, "packages", "db", "migrations");
  const migrationFiles = await readdir(migrationsDir);
  const columnNames: string[] = [];
  for (const file of migrationFiles) {
    if (!file.endsWith(".ts")) continue;
    const content = await readFile(path.join(migrationsDir, file), "utf8");
    const matches = [...content.matchAll(/table\.\w+\("([^"]+)"\)/g)];
    for (const match of matches) {
      columnNames.push(match[1]);
    }
  }
  const forbiddenTokens = [
    "sdjwt",
    "sd_jwt",
    "presentation",
    "claims",
    "payload",
    "jwt",
    "token",
    "vc"
  ];
  for (const column of columnNames) {
    const normalized = column.toLowerCase();
    if (
      normalized.endsWith("_hash") ||
      normalized.endsWith("_fingerprint") ||
      normalized === "payload_meta" ||
      normalized === "vct" ||
      normalized === "output_vct" ||
      normalized === "presentation_templates" ||
      normalized === "presentation_template"
    ) {
      continue;
    }
    if (forbiddenTokens.some((token) => normalized.includes(token))) {
      throw new Error(`raw_storage_column_failed: ${column}`);
    }
  }

  const db = await getDb();
  const jwtPrefix = "eyJ%";
  const checks = [
    { table: "issuance_events", column: "credential_fingerprint" },
    { table: "anchor_outbox", column: "payload_hash" },
    { table: "anchor_receipts", column: "payload_hash" },
    { table: "verification_challenges", column: "challenge_hash" },
    { table: "rate_limit_events", column: "subject_hash" },
    { table: "audit_logs", column: "data_hash" },
    { table: "obligations_executions", column: "anchor_payload_hash" },
    { table: "obligation_events", column: "event_hash" }
  ];
  for (const check of checks) {
    const row = await db(check.table).where(check.column, "like", jwtPrefix).first();
    assert.equal(row, undefined, `jwt_like_storage_found:${check.table}.${check.column}`);
  }

  const outboxRows = await db("anchor_outbox").select("payload_meta");
  const forbiddenMetaPatterns = ["did:", "nonce", "eyJ", "~"];
  for (const row of outboxRows) {
    const meta = row.payload_meta;
    const text = typeof meta === "string" ? meta : JSON.stringify(meta ?? {});
    if (forbiddenMetaPatterns.some((pattern) => text.includes(pattern))) {
      throw new Error("anchor_outbox_payload_meta_violation");
    }
  }
};

run().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
