import { strict as assert } from "node:assert";
import path from "node:path";
import { rm } from "node:fs/promises";
import { loadConfig } from "../core/config.js";
import { createFileVault } from "../core/vault/fileVault.js";
import { addCredential } from "../core/vault/records.js";
import {
  buildKbJwtBinding,
  buildVerifyRequest,
  computeSdHash
} from "../core/presentation/index.js";
import { createSoftwareKeyManager } from "../core/keys/softwareKeyManager.js";
import { hashes, verify } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
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

await run("credential stored encrypted", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "true";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
  const config = loadConfig();
  const baseDir = path.resolve(process.cwd(), "apps", "mobile-wallet", ".tmp-test-2");
  const vault = createFileVault({ baseDir, keyMaterial: config.WALLET_VAULT_KEY });
  await vault.init();
  await addCredential(vault, {
    sdJwt: "sdjwt.test.credential",
    network: "testnet"
  });
  const raw = await import("node:fs/promises").then((m) =>
    m.readFile(path.join(baseDir, "wallet.vault.json"), "utf8")
  );
  assert.ok(!raw.includes("sdjwt.test.credential"));
  await rm(baseDir, { recursive: true, force: true });
});

await run("kbjwt binding contains expected claims", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "true";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  const config = loadConfig();
  const baseDir = path.resolve(process.cwd(), "apps", "mobile-wallet", ".tmp-test-3");
  const vault = createFileVault({ baseDir, keyMaterial: config.WALLET_VAULT_KEY });
  await vault.init();
  const keyManager = createSoftwareKeyManager({ config, vault });
  const holderKeyRef = await keyManager.generateHolderKeypair();
  const kbJwt = await buildKbJwtBinding({
    keyManager,
    holderKeyRef,
    audience: "cuncta.action:demo",
    nonce: "nonce-123",
    expiresInSeconds: 60,
    sdJwtPresentation: "sd~jwt~presentation~",
    nowSeconds: 1000
  });
  const payloadPart = kbJwt.split(".")[1];
  assert.ok(payloadPart);
  const payloadJson = Buffer.from(payloadPart, "base64url").toString("utf8");
  const payload = JSON.parse(payloadJson) as Record<string, unknown>;
  assert.equal(payload.aud, "cuncta.action:demo");
  assert.equal(payload.nonce, "nonce-123");
  assert.equal(payload.exp, 1060);
  await rm(baseDir, { recursive: true, force: true });
});

await run("kbjwt signature verifies with embedded jwk", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "true";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  const config = loadConfig();
  const baseDir = path.resolve(process.cwd(), "apps", "mobile-wallet", ".tmp-test-4");
  const vault = createFileVault({ baseDir, keyMaterial: config.WALLET_VAULT_KEY });
  await vault.init();
  const keyManager = createSoftwareKeyManager({ config, vault });
  const holderKeyRef = await keyManager.generateHolderKeypair();
  const kbJwt = await buildKbJwtBinding({
    keyManager,
    holderKeyRef,
    audience: "cuncta.action:demo",
    nonce: "nonce-123",
    expiresInSeconds: 60,
    sdJwtPresentation: "sd~jwt~presentation~",
    nowSeconds: 1000
  });
  const [headerB64, payloadB64, signatureB64] = kbJwt.split(".");
  assert.ok(headerB64 && payloadB64 && signatureB64);
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
  assert.equal(header.alg, "EdDSA");
  const cnf = (payload.cnf as { jwk?: Record<string, unknown> } | undefined) ?? {};
  const jwk = cnf.jwk as { x?: string } | undefined;
  assert.ok(typeof jwk?.x === "string");
  const publicKey = Buffer.from(jwk.x, "base64url");
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
  const signature = Buffer.from(signatureB64, "base64url");
  const verified = await verify(signature, signingInput, publicKey);
  assert.equal(verified, true);
  assert.equal(typeof payload.exp, "number");
  assert.ok((payload.exp as number) > 1000);
  await rm(baseDir, { recursive: true, force: true });
});

await run("kbjwt sd_hash matches presentation hash", async () => {
  process.env.NODE_ENV = "development";
  process.env.WALLET_BUILD_MODE = "development";
  process.env.WALLET_ALLOW_SOFTWARE_KEYS = "true";
  process.env.APP_GATEWAY_BASE_URL = "http://localhost:3010";
  process.env.WALLET_VAULT_KEY = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
  const config = loadConfig();
  const baseDir = path.resolve(process.cwd(), "apps", "mobile-wallet", ".tmp-test-5");
  const vault = createFileVault({ baseDir, keyMaterial: config.WALLET_VAULT_KEY });
  await vault.init();
  const keyManager = createSoftwareKeyManager({ config, vault });
  const holderKeyRef = await keyManager.generateHolderKeypair();
  const sdJwtPresentation = "sd~jwt~presentation~";
  const kbJwt = await buildKbJwtBinding({
    keyManager,
    holderKeyRef,
    audience: "cuncta.action:demo",
    nonce: "nonce-123",
    expiresInSeconds: 60,
    sdJwtPresentation,
    nowSeconds: 1000
  });
  const payloadPart = kbJwt.split(".")[1];
  assert.ok(payloadPart);
  const payload = JSON.parse(Buffer.from(payloadPart, "base64url").toString("utf8")) as Record<
    string,
    unknown
  >;
  assert.equal(payload.sd_hash, computeSdHash(sdJwtPresentation));
  await rm(baseDir, { recursive: true, force: true });
});

await run("verify request assembly", async () => {
  const request = buildVerifyRequest({
    sdJwtPresentation: "sd~jwt~presentation~",
    kbJwt: "kb.jwt.token",
    nonce: "nonce-123",
    audience: "cuncta.action:demo"
  });
  assert.equal(request.presentation, "sd~jwt~presentation~kb.jwt.token");
  assert.equal(request.nonce, "nonce-123");
  assert.equal(request.audience, "cuncta.action:demo");
});
