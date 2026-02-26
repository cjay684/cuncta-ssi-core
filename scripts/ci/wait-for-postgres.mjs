import { setTimeout as sleep } from "node:timers/promises";
import net from "node:net";

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL || !DATABASE_URL.trim()) {
  console.error("DATABASE_URL missing (required to wait for Postgres)");
  process.exit(1);
}

const timeoutMs = Number(process.env.CI_POSTGRES_WAIT_TIMEOUT_MS ?? 60_000);
const started = Date.now();
const parsedDbUrl = new URL(DATABASE_URL);
const dbHost = parsedDbUrl.hostname || "localhost";
const dbPort = Number(parsedDbUrl.port || "5432");

const logAttempt = (attempt, msg) => {
  if (process.env.CI_POSTGRES_WAIT_QUIET === "1") return;
  console.log(`[ci] postgres_wait attempt=${attempt} ${msg}`);
};

const tryOnce = async () =>
  await new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: dbHost, port: dbPort });
    socket.setTimeout(2_000);
    socket.once("connect", () => {
      socket.end();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new Error("tcp_connect_timeout"));
    });
    socket.once("error", (error) => {
      socket.destroy();
      reject(error);
    });
  });

let attempt = 0;
let delayMs = 250;
while (Date.now() - started < timeoutMs) {
  attempt += 1;
  try {
    await tryOnce();
    logAttempt(attempt, "ok");
    process.exit(0);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    logAttempt(attempt, `not_ready reason=${msg.slice(0, 120)}`);
  }
  await sleep(delayMs);
  delayMs = Math.min(2_000, Math.round(delayMs * 1.6));
}

console.error(`[ci] postgres_wait timeout after ${timeoutMs}ms`);
process.exit(1);

