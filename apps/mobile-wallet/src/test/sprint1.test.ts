import { strict as assert } from "node:assert";
import path from "node:path";
import { readFile, rm } from "node:fs/promises";
import {
  AccountId,
  Client,
  Hbar,
  PrivateKey,
  PublicKey,
  TopicMessageSubmitTransaction,
  Transaction,
  TransactionId
} from "@hashgraph/sdk";
import * as DidMessages from "@hiero-did-sdk/messages";
import { loadConfig, assertSoftwareKeysAllowed } from "../core/config.js";
import { deriveUserPaysLimits } from "../core/did/limits.js";
import { createFileVault } from "../core/vault/fileVault.js";

const DIDOwnerMessage =
  DidMessages.DIDOwnerMessage ??
  (
    DidMessages as unknown as {
      default?: { DIDOwnerMessage?: typeof DidMessages.DIDOwnerMessage };
    }
  ).default?.DIDOwnerMessage;

if (!DIDOwnerMessage) {
  throw new Error("DIDOwnerMessage export not found");
}

const run = async (name: string, fn: () => Promise<void>) => {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (error) {
    console.error(`not ok - ${name}`);
    console.error(error instanceof Error ? (error.stack ?? error.message) : error);
    process.exitCode = 1;
  }
};

// Keep tests deterministic regardless of developer `.env`.
process.env.HEDERA_NETWORK = "testnet";
process.env.ALLOW_MAINNET = "false";

await run("software keys blocked without explicit allow", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "false";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const config = loadConfig();
  assert.throws(() => assertSoftwareKeysAllowed(config));
});

await run("software keys blocked in production mode", async () => {
  process.env.NODE_ENV = "production";
  process.env.WALLET_BUILD_MODE = "production";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "true";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const config = loadConfig();
  assert.throws(() => assertSoftwareKeysAllowed(config));
});

await run("mainnet requires ALLOW_MAINNET", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "false";
  process.env.HEDERA_NETWORK = "mainnet";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  process.env.ALLOW_MAINNET = "false";
  assert.throws(() => loadConfig());
});

await run("vault encrypts at rest", async () => {
  const baseDir = path.resolve(process.cwd(), "apps", "mobile-wallet", ".tmp-test");
  const keyMaterial = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const vault = createFileVault({ baseDir, keyMaterial });
  await vault.init();
  const state = await vault.getState();
  state.didRecord = {
    did: "did:hedera:testnet:example",
    holderKeyRef: { id: "holder-1", type: "holder" },
    network: "testnet",
    createdAt: new Date().toISOString()
  };
  await vault.setState(state);
  const raw = await readFile(path.join(baseDir, "wallet.vault.json"), "utf8");
  assert.ok(!raw.includes("did:hedera"));
  await rm(baseDir, { recursive: true, force: true });
});

await run("transaction message round-trip", async () => {
  const publicKey = PublicKey.fromBytesED25519(new Uint8Array(32).fill(7));
  const message = new DIDOwnerMessage({
    publicKey,
    network: "testnet",
    topicId: "0.0.12345"
  });
  message.signature = new Uint8Array(64).fill(8);
  const client = Client.forName("testnet");
  const payerAccount = AccountId.fromString("0.0.1001");
  const payerKey = PrivateKey.generateED25519();
  const tx = new TopicMessageSubmitTransaction()
    .setTopicId("0.0.12345")
    .setMessage(message.payload)
    .setTransactionId(TransactionId.generate(payerAccount))
    .setMaxTransactionFee(Hbar.fromTinybars(1))
    .freezeWith(client);
  const signed = await tx.sign(payerKey);
  if (typeof client.close === "function") {
    client.close();
  }
  const parsedTx = Transaction.fromBytes(signed.toBytes());
  if (!(parsedTx instanceof TopicMessageSubmitTransaction)) {
    throw new Error("parsed transaction type mismatch");
  }
  const parsedAny = parsedTx as unknown as { message?: Uint8Array };
  const parsedMessage = parsedAny.message ?? new Uint8Array();
  assert.equal(
    Buffer.from(parsedMessage).toString("base64url"),
    Buffer.from(message.payload).toString("base64url")
  );
});

await run("user pays limits: expiry invalid", async () => {
  assert.throws(() =>
    deriveUserPaysLimits({
      walletMaxFeeTinybars: 100,
      requestExpiresAt: "not-a-date",
      nowMs: Date.now()
    })
  );
});

await run("user pays limits: expired with skew", async () => {
  const now = Date.now();
  const expiresAt = new Date(now + 2000).toISOString();
  assert.throws(() =>
    deriveUserPaysLimits({
      walletMaxFeeTinybars: 100,
      requestExpiresAt: expiresAt,
      nowMs: now,
      skewMs: 4000
    })
  );
});

await run("user pays limits: fee caps to gateway", async () => {
  const now = Date.now();
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: 500,
    gatewayMaxFeeTinybars: 200,
    requestExpiresAt: new Date(now + 60_000).toISOString(),
    nowMs: now
  });
  assert.equal(limits.effectiveMaxFeeTinybars, 200);
});

await run("user pays limits: fee uses wallet when gateway absent", async () => {
  const now = Date.now();
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: 500,
    requestExpiresAt: new Date(now + 60_000).toISOString(),
    nowMs: now
  });
  assert.equal(limits.effectiveMaxFeeTinybars, 500);
});

await run("user pays limits: expiry boundary", async () => {
  const now = Date.now();
  const expiresAt = new Date(now + 4000).toISOString();
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: 100,
    requestExpiresAt: expiresAt,
    nowMs: now,
    skewMs: 4000
  });
  assert.equal(limits.effectiveExpiryMs, Date.parse(expiresAt) - 4000);
});

await run("user pays limits: signed tx too large", async () => {
  const now = Date.now();
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: 500,
    gatewayMaxFeeTinybars: 500,
    gatewayMaxTxBytes: 10,
    requestExpiresAt: new Date(now + 60_000).toISOString(),
    nowMs: now
  });
  assert.equal(limits.gatewayMaxTxBytes, 10);
});

await run("user pays limits: gateway maxTxBytes omitted", async () => {
  const now = Date.now();
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: 500,
    requestExpiresAt: new Date(now + 60_000).toISOString(),
    nowMs: now
  });
  assert.equal(limits.gatewayMaxTxBytes, undefined);
});

await run("user pays limits: invalid ttl ignored", async () => {
  const now = Date.now();
  const limits = deriveUserPaysLimits({
    walletMaxFeeTinybars: 500,
    gatewayRequestTtlSeconds: 0,
    requestExpiresAt: new Date(now + 60_000).toISOString(),
    nowMs: now
  });
  assert.equal(limits.requestTtlSeconds, undefined);
});
