import { test } from "node:test";
import assert from "node:assert/strict";
import dotenv from "dotenv";
import path from "node:path";
import { createDb, runMigrations } from "@cuncta/db";

dotenv.config({
  path: path.resolve(process.cwd(), "../../.env")
});

test("fails startup when privacy erase epoch regresses", async () => {
  process.env.NODE_ENV = "production";
  process.env.BACKUP_RESTORE_MODE = "false";
  process.env.PSEUDONYMIZER_PEPPER = "pepper-test-restore-epoch-123456";
  process.env.PRIVACY_ERASE_EPOCH_EXPECTED = "2";
  process.env.DATABASE_URL =
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi";

  const db = createDb(process.env.DATABASE_URL);
  try {
    await runMigrations(db);
    await db("system_metadata").where({ key: "privacy_erase_epoch" }).del();
    await db("system_metadata").where({ key: "pseudonymizer_fingerprint" }).del();
    await db("anchor_receipts").del();
    await db("anchor_outbox").del();
    await db("issuer_keys").where({ kid: "issuer-test-active" }).del();

    await db("issuer_keys").insert({
      kid: "issuer-test-active",
      public_jwk: { kty: "OKP", crv: "Ed25519", x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
      private_jwk: null,
      status: "ACTIVE",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    });

    await db("system_metadata")
      .insert({
        key: "privacy_erase_epoch",
        value: "1",
        updated_at: new Date().toISOString()
      })
      .onConflict("key")
      .merge({ value: "1", updated_at: new Date().toISOString() });

    const { getPepperFingerprint } = await import("./pseudonymizer.js");
    await db("system_metadata")
      .insert({
        key: "pseudonymizer_fingerprint",
        value: getPepperFingerprint(),
        updated_at: new Date().toISOString()
      })
      .onConflict("key")
      .merge({
        value: getPepperFingerprint(),
        updated_at: new Date().toISOString()
      });

    const { runStartupIntegrityChecks } = await import("./restoreValidation.js");
    await assert.rejects(() => runStartupIntegrityChecks(), /restore_epoch_regression/);
  } finally {
    await db.destroy();
  }
});
