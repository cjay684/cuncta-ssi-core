import { createHash, randomBytes } from "node:crypto";
import {
  createHmacSha256Pseudonymizer,
  createSha256Pseudonymizer,
  type Pseudonymizer
} from "@cuncta/shared";
import { config } from "./config.js";
import { log } from "./log.js";
import { getDb } from "./db.js";
import { metrics } from "./metrics.js";

let hmacPseudonymizer: Pseudonymizer | null = null;
let generatedPepper: string | null = null;
let warnedMissingPepper = false;
let warnedLegacy = false;
let warnedMismatch = false;
let warnedLegacyRows = false;

const legacyPseudonymizer = createSha256Pseudonymizer();
const FINGERPRINT_KEY = "pseudonymizer_fingerprint";
const LEGACY_ROWS_KEY = "pseudonymizer_legacy_rows_present";
const FINGERPRINT_SALT = "cuncta-pseudonymizer-v1";

const getPepper = () => {
  if (config.PSEUDONYMIZER_PEPPER) {
    return config.PSEUDONYMIZER_PEPPER;
  }
  if (config.NODE_ENV === "production") {
    throw new Error("pseudonymizer_pepper_missing");
  }
  if (!generatedPepper) {
    generatedPepper = randomBytes(32).toString("base64url");
  }
  if (!warnedMissingPepper) {
    warnedMissingPepper = true;
    log.warn("pseudonymizer.pepper.missing", { env: config.NODE_ENV });
  }
  return generatedPepper;
};

const getPrimaryPseudonymizer = () => {
  if (!hmacPseudonymizer) {
    hmacPseudonymizer = createHmacSha256Pseudonymizer({ pepper: getPepper() });
  }
  return hmacPseudonymizer;
};

const getLegacyHash = (did: string) => {
  if (!config.PSEUDONYMIZER_ALLOW_LEGACY) return null;
  if (config.NODE_ENV === "production") {
    throw new Error("pseudonymizer_legacy_disabled");
  }
  if (!warnedLegacy) {
    warnedLegacy = true;
    log.warn("pseudonymizer.legacy_enabled", { env: config.NODE_ENV });
  }
  return legacyPseudonymizer.didToHash(did);
};

export const getDidHashes = (did: string) => {
  const primary = getPrimaryPseudonymizer().didToHash(did);
  const legacy = getLegacyHash(did);
  return { primary, legacy };
};

export const getLookupHashes = (hashes: { primary: string; legacy?: string | null }) =>
  hashes.legacy ? [hashes.primary, hashes.legacy] : [hashes.primary];

export const getPepperFingerprint = () =>
  createHash("sha256").update(`${FINGERPRINT_SALT}${getPepper()}`).digest("hex");

const detectLegacyRows = async (db: Awaited<ReturnType<typeof getDb>>) => {
  const [issuance, auraSignals, obligations, rateLimits] = await Promise.all([
    db("issuance_events").select("subject_did_hash").whereNotNull("subject_did_hash").first(),
    db("aura_signals").select("subject_did_hash").first(),
    db("obligations_executions").select("subject_did_hash").first(),
    db("rate_limit_events").select("subject_hash").first()
  ]);
  return Boolean(issuance || auraSignals || obligations || rateLimits);
};

export const ensurePseudonymizerConsistency = async () => {
  const db = await getDb();
  const fingerprint = getPepperFingerprint();
  const now = new Date().toISOString();
  const existing = await db("system_metadata").where({ key: FINGERPRINT_KEY }).first();
  if (!existing) {
    await db("system_metadata")
      .insert({ key: FINGERPRINT_KEY, value: fingerprint, created_at: now, updated_at: now })
      .onConflict("key")
      .merge({ value: fingerprint, updated_at: now });
  } else if (existing.value !== fingerprint) {
    if (config.NODE_ENV === "production") {
      throw new Error("pseudonymizer_mismatch");
    }
    if (!warnedMismatch) {
      warnedMismatch = true;
      log.warn("pseudonymizer.mismatch", {
        expected: existing.value,
        actual: fingerprint,
        env: config.NODE_ENV
      });
    }
  }

  let legacyRowsPresent = false;
  const legacyFlag = await db("system_metadata").where({ key: LEGACY_ROWS_KEY }).first();
  if (legacyFlag) {
    legacyRowsPresent = legacyFlag.value === "1";
  } else {
    const anyRows = await detectLegacyRows(db);
    if (anyRows && (!existing || !config.PSEUDONYMIZER_ALLOW_LEGACY)) {
      legacyRowsPresent = true;
      await db("system_metadata")
        .insert({ key: LEGACY_ROWS_KEY, value: "1", created_at: now, updated_at: now })
        .onConflict("key")
        .merge({ value: "1", updated_at: now });
    }
  }

  metrics.setGauge("legacy_rows_present", {}, legacyRowsPresent ? 1 : 0);
  if (!config.PSEUDONYMIZER_ALLOW_LEGACY && legacyRowsPresent && !warnedLegacyRows) {
    warnedLegacyRows = true;
    log.warn("pseudonymizer.legacy_rows_present", { env: config.NODE_ENV });
  }
};

export const ensurePseudonymizerReady = () => {
  getPrimaryPseudonymizer();
};
