import { getDb } from "./db.js";
import { ensurePseudonymizerConsistency } from "./pseudonymizer.js";
import {
  getPrivacyEraseEpoch,
  incrementStartupIntegrityFailure,
  getPrivacyEraseEver
} from "./audit.js";
import { log } from "./log.js";
import { config } from "./config.js";

export const runStartupIntegrityChecks = async () => {
  try {
    await ensurePseudonymizerConsistency();

    const db = await getDb();
    const activeKeys = await db("issuer_keys").where({ status: "ACTIVE" });
    if (!activeKeys.length) {
      throw new Error("issuer_active_key_missing");
    }

    const latestKeyAnchor = await db("anchor_outbox")
      .join("anchor_receipts", "anchor_outbox.payload_hash", "anchor_receipts.payload_hash")
      .whereIn("anchor_outbox.event_type", ["ISSUER_KEY_ROTATE", "ISSUER_KEY_REVOKE"])
      .orderBy("anchor_receipts.created_at", "desc")
      .first();
    if (latestKeyAnchor?.created_at) {
      const anchorTime = Date.parse(String(latestKeyAnchor.created_at));
      for (const key of activeKeys) {
        const keyTime = Date.parse(String(key.created_at));
        if (Number.isFinite(anchorTime) && Number.isFinite(keyTime) && keyTime < anchorTime) {
          throw new Error("issuer_active_key_outdated");
        }
      }
    }

    const eraseEver = await getPrivacyEraseEver(db);
    const eraseEpoch = await getPrivacyEraseEpoch(db);
    if (config.NODE_ENV === "production" && !config.BACKUP_RESTORE_MODE) {
      if (config.PRIVACY_ERASE_EPOCH_EXPECTED === undefined) {
        throw new Error("privacy_erase_epoch_expected_required");
      }
      if (eraseEpoch < config.PRIVACY_ERASE_EPOCH_EXPECTED) {
        throw new Error("restore_epoch_regression");
      }
    }
    if (eraseEver) {
      const tombstoneCountRow = await db("privacy_tombstones")
        .count<{ count: string }>("did_hash as count")
        .first();
      const tombstoneCount = Number(tombstoneCountRow?.count ?? 0);
      if (tombstoneCount === 0) {
        throw new Error("privacy_tombstones_missing");
      }
    }
    if (eraseEpoch > 0) {
      const tombstoneCountRow = await db("privacy_tombstones")
        .count<{ count: string }>("did_hash as count")
        .first();
      const tombstoneCount = Number(tombstoneCountRow?.count ?? 0);
      if (tombstoneCount === 0) {
        throw new Error("privacy_tombstones_missing");
      }
    }
  } catch (error) {
    await incrementStartupIntegrityFailure();
    const message = error instanceof Error ? error.message : "startup_integrity_failed";
    log.error("startup.integrity.failed", { error: message });
    throw error;
  }
};
