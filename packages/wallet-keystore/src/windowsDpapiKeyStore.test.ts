import { strict as assert } from "node:assert";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { hashes, verify } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { selectWalletKeyStore } from "./select.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

const run = async () => {
  if (process.platform !== "win32") {
    console.log("windows dpapi keystore: skipped (non-windows)");
    return;
  }
  const dir = await mkdtemp(path.join(os.tmpdir(), "cuncta-wallet-dpapi-"));
  try {
    delete process.env.NODE_ENV;
    delete process.env.ALLOW_INSECURE_WALLET_KEYS;
    const store = selectWalletKeyStore({ walletDir: dir, mode: "dpapi" });
    const key = await store.ensureKey("primary");
    const payload = Buffer.from("did-payload-to-sign", "utf8");
    const sig = await store.sign("primary", payload);
    const ok = await verify(sig, payload, key.publicKey);
    assert.equal(ok, true);
    console.log("windows dpapi keystore: ok");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
};

await run();

