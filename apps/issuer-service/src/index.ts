import { log } from "./log.js";
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

const { config } = await import("./config.js");
const { ISSUER_DID } = await import("./issuer/identity.js");
const { getDb } = await import("./db.js");
const { startAnchorWorker } = await import("./hedera/anchorWorker.js");
const { startAuraWorker } = await import("./aura/auraWorker.js");
const { startCleanupWorker } = await import("./cleanup/cleanupWorker.js");
const { buildServer } = await import("./server.js");
const { runStartupIntegrityChecks } = await import("./restoreValidation.js");
const { ensureCatalogIntegrity } = await import("./catalogIntegrity.js");
const { ensureAuraRuleIntegrity } = await import("./aura/auraIntegrity.js");
const { enforceStrictDbRole } = await import("./dbRole.js");

const requireEnv = (names: string[]) => {
  const missing = names.filter(
    (name) => !process.env[name] || String(process.env[name]).trim() === ""
  );
  if (missing.length) {
    throw new Error(`missing_required_envs:${missing.join(",")}`);
  }
};

const requireOneOf = (names: string[], label: string) => {
  const hasAny = names.some((name) => process.env[name] && String(process.env[name]).trim() !== "");
  if (!hasAny) {
    throw new Error(`missing_required_envs:${label}`);
  }
};

if (config.NODE_ENV === "production") {
  requireEnv([
    "DATABASE_URL",
    "ISSUER_BASE_URL",
    "PSEUDONYMIZER_PEPPER",
    "SERVICE_JWT_SECRET_ISSUER",
    "POLICY_SIGNING_JWK",
    "ANCHOR_AUTH_SECRET"
  ]);
  requireOneOf(
    ["HEDERA_OPERATOR_ID_ANCHOR", "HEDERA_OPERATOR_ID"],
    "HEDERA_OPERATOR_ID_ANCHOR|HEDERA_OPERATOR_ID"
  );
  requireOneOf(
    ["HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR", "HEDERA_OPERATOR_PRIVATE_KEY"],
    "HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR|HEDERA_OPERATOR_PRIVATE_KEY"
  );
}

if (config.NODE_ENV === "production" && !isPrivateBindAddress(config.SERVICE_BIND_ADDRESS)) {
  throw new Error("refusing_to_bind_publicly_in_production");
}

await getDb();
await enforceStrictDbRole();
if (config.NODE_ENV === "production") {
  await runStartupIntegrityChecks();
}
const bootstrapIntegrityAudits = async () => {
  const db = await getDb();
  const catalogs = await db("credential_types").select("*");
  for (const row of catalogs) {
    await ensureCatalogIntegrity(row);
  }
  const auraRules = await db("aura_rules").select("*");
  for (const rule of auraRules) {
    await ensureAuraRuleIntegrity(rule);
  }
};
await bootstrapIntegrityAudits();
startAnchorWorker();
startAuraWorker();
startCleanupWorker();
const app = buildServer();
log.info("issuer.did", { issuerDid: ISSUER_DID });

app
  .listen({ port: config.PORT, host: config.SERVICE_BIND_ADDRESS })
  .then((address) => {
    log.info("listening", { address });
  })
  .catch((error) => {
    log.error("failed to start", { error });
    process.exit(1);
  });
