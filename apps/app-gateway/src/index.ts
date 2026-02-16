import { log } from "./log.js";
import { config } from "./config.js";
import { buildServer } from "./server.js";
import { enforceStrictDbRole } from "./dbRole.js";
import net from "node:net";

const isPrivateBindAddress = (value: string) => {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed === "0.0.0.0" || trimmed === "::") return false;
  if (trimmed === "localhost") return true;
  const mapped = trimmed.startsWith("::ffff:") ? trimmed.slice(7) : trimmed;
  const ipType = net.isIP(mapped);
  if (ipType === 4) {
    const [a, b] = mapped.split(".").map((part) => Number(part));
    if ([a, b].some((part) => Number.isNaN(part))) return false;
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    return false;
  }
  if (ipType === 6) {
    if (trimmed === "::1") return true;
    if (trimmed.startsWith("fc") || trimmed.startsWith("fd")) return true;
    if (
      trimmed.startsWith("fe8") ||
      trimmed.startsWith("fe9") ||
      trimmed.startsWith("fea") ||
      trimmed.startsWith("feb")
    ) {
      return true;
    }
  }
  return false;
};

const requireEnv = (names: string[]) => {
  const missing = names.filter(
    (name) => !process.env[name] || String(process.env[name]).trim() === ""
  );
  if (missing.length) {
    throw new Error(`missing_required_envs:${missing.join(",")}`);
  }
};

if (config.NODE_ENV === "production") {
  requireEnv([
    "SERVICE_JWT_SECRET",
    "SERVICE_JWT_SECRET_DID",
    "SERVICE_JWT_SECRET_ISSUER",
    "SERVICE_JWT_SECRET_VERIFIER",
    "DID_SERVICE_BASE_URL",
    "ISSUER_SERVICE_BASE_URL",
    "PSEUDONYMIZER_PEPPER"
  ]);
}

if (config.NODE_ENV === "production" && !isPrivateBindAddress(config.SERVICE_BIND_ADDRESS)) {
  throw new Error("refusing_to_bind_publicly_in_production");
}

const app = buildServer();
await enforceStrictDbRole();

app
  .listen({ port: config.PORT, host: config.SERVICE_BIND_ADDRESS })
  .then((address) => {
    log.info("listening", { address });
  })
  .catch((error) => {
    log.error("failed to start", { error });
    process.exit(1);
  });
