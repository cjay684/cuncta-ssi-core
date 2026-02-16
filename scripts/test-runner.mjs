import { readdir } from "node:fs/promises";
import path from "node:path";
import { Worker } from "node:worker_threads";

const walk = async (dir, acc = []) => {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === "node_modules" || entry.name === "dist" || entry.name.startsWith(".")) {
      continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await walk(full, acc);
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".test.ts")) {
      acc.push(full);
    }
  }
  return acc;
};

const runWorker = (workerUrl, file, timeoutMs) =>
  new Promise((resolve, reject) => {
    const worker = new Worker(workerUrl, {
      workerData: { file },
      execArgv: ["--loader", "ts-node/esm"]
    });
    const timeout = setTimeout(() => {
      worker.terminate().finally(() => {
        reject(new Error(`Test timeout: ${file}`));
      });
    }, timeoutMs);
    worker.on("error", reject);
    worker.on("exit", (code) => {
      clearTimeout(timeout);
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`Test failed: ${file}`));
      }
    });
  });

const probeDb = async () => {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    return { available: false, reason: "DATABASE_URL not set" };
  }
  let db;
  try {
    const { createDb } = await import("../packages/db/src/index.ts");
    db = createDb(databaseUrl);
    await Promise.race([
      db.raw("select 1"),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("database probe timeout")), 3_000)
      )
    ]);
    return { available: true };
  } catch (error) {
    const reason =
      error instanceof Error ? (error.message || error.name) : "unknown database error";
    return { available: false, reason };
  } finally {
    if (db) {
      await db.destroy().catch(() => undefined);
    }
  }
};

export const runServiceTests = async (input) => {
  const {
    srcRoot,
    workerUrl,
    requiresDb,
    requiresIntegration = () => false,
    testTimeoutMs = Number(process.env.TEST_TIMEOUT_MS ?? 120000)
  } = input;

  const files = await walk(srcRoot);
  const dbRequested = process.env.RUN_DB_TESTS === "1" || Boolean(process.env.DATABASE_URL);
  if (process.env.RUN_DB_TESTS === "1" && !process.env.DATABASE_URL) {
    throw new Error("RUN_DB_TESTS=1 requires DATABASE_URL to be set.");
  }
  const dbProbe = dbRequested ? await probeDb() : { available: false };
  if (dbRequested && !dbProbe.available) {
    console.log(`DB tests will be skipped (${dbProbe.reason ?? "database unavailable"})`);
  }

  for (const file of files) {
    const relative = path.relative(srcRoot, file);
    if (process.env.RUN_TESTNET_INTEGRATION !== "1" && requiresIntegration(file)) {
      console.log(
        `skipped - ${relative} (set RUN_TESTNET_INTEGRATION=1 to run integration tests)`
      );
      continue;
    }
    if (requiresDb(file) && !dbProbe.available) {
      console.log(`skipped - ${relative} (database unavailable)`);
      continue;
    }
    console.log(`running - ${relative}`);
    await runWorker(workerUrl, file, testTimeoutMs);
  }
};
