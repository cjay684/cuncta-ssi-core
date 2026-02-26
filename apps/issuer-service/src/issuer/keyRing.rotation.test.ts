import { test } from "node:test";
import assert from "node:assert/strict";
import { exportJWK, generateKeyPair } from "jose";
import { createDb, runMigrations } from "@cuncta/db";

test("rotate and revoke issuer key (happy path)", async () => {
  process.env.NODE_ENV = "development";
  process.env.ISSUER_BASE_URL = "http://localhost:3002";
  process.env.ISSUER_KEYS_BOOTSTRAP = "true";
  process.env.ISSUER_KEYS_ALLOW_DB_PRIVATE = "true";
  process.env.ANCHOR_AUTH_SECRET = "test-anchor-secret";

  const { privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "issuer-test-1";
  process.env.ISSUER_JWK = JSON.stringify(jwk);

  const { ensureIssuerKeys, rotateIssuerKey, revokeIssuerKey } = await import("./keyRing.js");

  const db = createDb(
    process.env.DATABASE_URL ?? "postgres://cuncta:cuncta@localhost:5432/cuncta_ssi"
  );
  try {
    await runMigrations(db);
    await db("anchor_outbox").del();
    await db("issuer_keys").del();
    await db("audit_logs").del();

    await ensureIssuerKeys();
    const { kid } = await rotateIssuerKey();
    const active = await db("issuer_keys").where({ status: "ACTIVE" }).first();
    assert.equal(active?.kid, kid);

    await revokeIssuerKey(kid);
    const revoked = await db("issuer_keys").where({ kid }).first();
    assert.equal(revoked?.status, "REVOKED");
  } finally {
    await db.destroy();
  }
});
