import { strict as assert } from "node:assert";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { selectWalletKeyStore } from "./select.js";

const run = async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "cuncta-wallet-keystore-"));
  try {
    delete process.env.NODE_ENV;
    delete process.env.ALLOW_INSECURE_WALLET_KEYS;
    delete process.env.WALLET_KEYSTORE;
    const store = selectWalletKeyStore({ walletDir: dir, mode: "file" });
    const k1 = await store.ensureKey("primary");
    const loaded = await store.loadKey("primary");
    assert.ok(loaded);
    assert.equal(loaded?.publicKeyMultibase, k1.publicKeyMultibase);

    // Production posture: file keystore is disabled unless explicitly allowed.
    process.env.NODE_ENV = "production";
    let prodThrew = false;
    try {
      selectWalletKeyStore({ walletDir: dir, mode: "file" });
    } catch (e) {
      prodThrew = true;
      assert.equal((e as Error).message, "insecure_file_keystore_disabled_in_production");
    }
    assert.equal(prodThrew, true);
    process.env.ALLOW_INSECURE_WALLET_KEYS = "true";
    const prodAllowed = selectWalletKeyStore({ walletDir: dir, mode: "file" });
    await prodAllowed.ensureKey("primary");

    // DPAPI provider exists only on Windows.
    if (process.platform === "win32") {
      const dpapi = selectWalletKeyStore({ walletDir: dir, mode: "dpapi" });
      const pub = await dpapi.ensureKey("primary");
      assert.equal(pub.alg, "Ed25519");
    } else {
      let dpapiThrew = false;
      try {
        selectWalletKeyStore({ walletDir: dir, mode: "dpapi" });
      } catch (e) {
        dpapiThrew = true;
        assert.equal((e as Error).message, "wallet_keystore_dpapi_unavailable");
      }
      assert.equal(dpapiThrew, true);
    }

    let threw = false;
    try {
      selectWalletKeyStore({ walletDir: dir, mode: "hardware" });
    } catch (e) {
      threw = true;
      assert.equal((e as Error).message, "wallet_keystore_hardware_unavailable");
    }
    assert.equal(threw, true);

    let mobileThrew = false;
    try {
      selectWalletKeyStore({ walletDir: dir, mode: "mobile" });
    } catch (e) {
      mobileThrew = true;
      assert.equal((e as Error).message, "wallet_keystore_mobile_unavailable");
    }
    assert.equal(mobileThrew, true);

    let webcryptoThrew = false;
    try {
      selectWalletKeyStore({ walletDir: dir, mode: "webcrypto" });
    } catch (e) {
      webcryptoThrew = true;
      assert.equal((e as Error).message, "wallet_keystore_webcrypto_unavailable");
    }
    assert.equal(webcryptoThrew, true);

    console.log("wallet-keystore selection: ok");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

await run();

