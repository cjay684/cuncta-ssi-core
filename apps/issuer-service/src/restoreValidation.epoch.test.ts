import { test } from "node:test";
import assert from "node:assert/strict";
import dotenv from "dotenv";
import path from "node:path";
import { createDb, runMigrations } from "@cuncta/db";

dotenv.config({
  path: path.resolve(process.cwd(), "../../.env")
});

test("fails startup when privacy erase epoch regresses", async () => {
  const TEST_SECRET_HEX = "0123456789abcdef".repeat(4);
  process.env.NODE_ENV = "production";
  process.env.BACKUP_RESTORE_MODE = "false";
  process.env.TRUST_PROXY = "true";
  process.env.SERVICE_BIND_ADDRESS = "127.0.0.1";
  process.env.ISSUER_BASE_URL = process.env.ISSUER_BASE_URL ?? "http://issuer.test";
  process.env.DID_SERVICE_BASE_URL = process.env.DID_SERVICE_BASE_URL ?? "http://did.test";
  process.env.ISSUER_DID = process.env.ISSUER_DID ?? "did:example:issuer";
  process.env.ISSUER_JWK =
    process.env.ISSUER_JWK ??
    JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "test",
      d: "test",
      alg: "EdDSA",
      kid: "issuer-1"
    });
  process.env.OID4VCI_TOKEN_SIGNING_JWK =
    process.env.OID4VCI_TOKEN_SIGNING_JWK ??
    JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "test",
      d: "test",
      alg: "EdDSA",
      kid: "oid4vci-token-1"
    });
  process.env.OID4VCI_TOKEN_SIGNING_BOOTSTRAP = "false";
  process.env.POLICY_SIGNING_JWK =
    process.env.POLICY_SIGNING_JWK ??
    JSON.stringify({
      kty: "OKP",
      crv: "Ed25519",
      x: "test",
      d: "test",
      alg: "EdDSA",
      kid: "policy-1"
    });
  process.env.ANCHOR_AUTH_SECRET = process.env.ANCHOR_AUTH_SECRET ?? "change-me-anchor-secret";
  process.env.SERVICE_JWT_SECRET = process.env.SERVICE_JWT_SECRET ?? TEST_SECRET_HEX;
  process.env.SERVICE_JWT_SECRET_ISSUER = process.env.SERVICE_JWT_SECRET_ISSUER ?? TEST_SECRET_HEX;
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
