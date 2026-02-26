import { readFile, writeFile, rm, mkdir } from "node:fs/promises";
import path from "node:path";
import { randomBytes, createHash, createCipheriv, createDecipheriv } from "node:crypto";
import { Vault, VaultState } from "./types.js";

type StoredEnvelope = {
  version: number;
  saltB64: string;
  ivB64: string;
  tagB64: string;
  ciphertextB64: string;
};

const emptyState = (): VaultState => ({
  holderKeys: {},
  payerKeys: {},
  credentials: {},
  relyingParties: {}
});

const deriveKey = (keyMaterial: Uint8Array, salt: Uint8Array) => {
  const hash = createHash("sha256");
  hash.update(keyMaterial);
  hash.update(salt);
  return hash.digest().subarray(0, 32);
};

const parseKeyMaterial = (value: string) => {
  const trimmed = value.trim();
  if (/^[a-fA-F0-9]+$/.test(trimmed)) {
    return new Uint8Array(Buffer.from(trimmed, "hex"));
  }
  return new Uint8Array(Buffer.from(trimmed, "base64url"));
};

const encrypt = (state: VaultState, keyMaterial: string): StoredEnvelope => {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(parseKeyMaterial(keyMaterial), salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(state), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    version: 1,
    saltB64: Buffer.from(salt).toString("base64url"),
    ivB64: Buffer.from(iv).toString("base64url"),
    tagB64: Buffer.from(tag).toString("base64url"),
    ciphertextB64: Buffer.from(ciphertext).toString("base64url")
  };
};

const decrypt = (envelope: StoredEnvelope, keyMaterial: string): VaultState => {
  if (envelope.version !== 1) {
    throw new Error("vault_version_unsupported");
  }
  const salt = Buffer.from(envelope.saltB64, "base64url");
  const iv = Buffer.from(envelope.ivB64, "base64url");
  const tag = Buffer.from(envelope.tagB64, "base64url");
  const ciphertext = Buffer.from(envelope.ciphertextB64, "base64url");
  const key = deriveKey(parseKeyMaterial(keyMaterial), salt);
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(plaintext.toString("utf8")) as VaultState;
};

export const createFileVault = (input: { baseDir: string; keyMaterial: string }): Vault => {
  const filePath = path.join(input.baseDir, "wallet.vault.json");

  return {
    async init() {
      try {
        await readFile(filePath, "utf8");
      } catch {
        await mkdir(input.baseDir, { recursive: true });
        await writeFile(filePath, JSON.stringify(encrypt(emptyState(), input.keyMaterial)), "utf8");
      }
    },
    async getState() {
      try {
        const content = await readFile(filePath, "utf8");
        const envelope = JSON.parse(content) as StoredEnvelope;
        return decrypt(envelope, input.keyMaterial);
      } catch {
        return emptyState();
      }
    },
    async setState(state) {
      await writeFile(filePath, JSON.stringify(encrypt(state, input.keyMaterial)), "utf8");
    },
    async wipe() {
      await rm(filePath, { force: true });
    }
  };
};
