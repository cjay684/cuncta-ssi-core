import { randomBytes } from "node:crypto";
import { WalletStore, type WalletState } from "@cuncta/wallet";
import { getPublicKey, hashes } from "@noble/ed25519";
import { sign } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { base58btc } from "multiformats/bases/base58";
import type { WalletKeyPurpose, WalletKeyStore } from "./types.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

const toBase64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const fromBase64 = (value: string) => new Uint8Array(Buffer.from(value, "base64"));

const toBase58Multibase = (publicKey: Uint8Array) => base58btc.encode(publicKey);

type StoredNodeKey = {
  privateKeyBase64: string;
  publicKeyBase64: string;
  publicKeyMultibase?: string;
};

type WalletStateWithKeystore = WalletState & {
  keystore?: Record<string, StoredNodeKey | undefined>;
};

const keyPath = (purpose: WalletKeyPurpose) => {
  if (purpose === "primary") return "ed25519";
  if (purpose === "holder") return "holder_ed25519";
  return "recovery_ed25519";
};

const readKey = (state: WalletState, purpose: WalletKeyPurpose) => {
  const bucket = (state as WalletStateWithKeystore).keystore ?? {};
  const entry = bucket[keyPath(purpose)];
  if (!entry || typeof entry !== "object") return null;
  const priv = String(entry.privateKeyBase64 ?? "");
  const pub = String(entry.publicKeyBase64 ?? "");
  const mb = String(entry.publicKeyMultibase ?? "");
  if (!priv || !pub) return null;
  return {
    privateKey: fromBase64(priv),
    publicKey: fromBase64(pub),
    publicKeyMultibase: mb || toBase58Multibase(fromBase64(pub))
  };
};

const writeKey = (
  state: WalletState,
  purpose: WalletKeyPurpose,
  material: { privateKey: Uint8Array; publicKey: Uint8Array; publicKeyMultibase: string }
) => {
  const root = state as WalletStateWithKeystore;
  const bucket = root.keystore ?? {};
  bucket[keyPath(purpose)] = {
    privateKeyBase64: toBase64(material.privateKey),
    publicKeyBase64: toBase64(material.publicKey),
    publicKeyMultibase: material.publicKeyMultibase
  };
  root.keystore = bucket;
};

export const createNodeFileKeyStore = (input: {
  walletDir: string;
  filename?: string;
}): WalletKeyStore => {
  const store = new WalletStore({
    walletDir: input.walletDir,
    filename: input.filename ?? "wallet-state.json"
  });

  const generate = async (purpose: WalletKeyPurpose) => {
    const privateKey = new Uint8Array(randomBytes(32));
    const publicKey = await getPublicKey(privateKey);
    return {
      purpose,
      alg: "Ed25519" as const,
      publicKey,
      privateKey,
      publicKeyMultibase: toBase58Multibase(publicKey)
    };
  };

  return {
    async ensureKey(purpose) {
      const state = await store.load();
      const existing = readKey(state, purpose);
      if (existing) {
        return {
          purpose,
          alg: "Ed25519",
          publicKey: existing.publicKey,
          publicKeyMultibase: existing.publicKeyMultibase
        };
      }
      const created = await generate(purpose);
      writeKey(state, purpose, created);
      await store.save(state);
      return {
        purpose,
        alg: "Ed25519",
        publicKey: created.publicKey,
        publicKeyMultibase: created.publicKeyMultibase
      };
    },
    async loadKey(purpose) {
      const state = await store.load();
      const existing = readKey(state, purpose);
      if (!existing) return null;
      return {
        purpose,
        alg: "Ed25519",
        publicKey: existing.publicKey,
        publicKeyMultibase: existing.publicKeyMultibase
      };
    },
    async sign(purpose, payload) {
      const state = await store.load();
      const existing = readKey(state, purpose);
      if (!existing) {
        throw new Error("wallet_key_missing");
      }
      return await sign(payload, existing.privateKey);
    },
    async saveKeyMaterial(key) {
      if (key.alg !== "Ed25519") {
        throw new Error("wallet_key_alg_unsupported");
      }
      const state = await store.load();
      writeKey(state, key.purpose, {
        privateKey: key.privateKey,
        publicKey: key.publicKey,
        publicKeyMultibase: key.publicKeyMultibase ?? toBase58Multibase(key.publicKey)
      });
      await store.save(state);
    },
    async deleteKey(purpose) {
      const state = await store.load();
      const root = state as WalletStateWithKeystore;
      const bucket = root.keystore ?? {};
      delete bucket[keyPath(purpose)];
      root.keystore = bucket;
      await store.save(state);
    }
  };
};
