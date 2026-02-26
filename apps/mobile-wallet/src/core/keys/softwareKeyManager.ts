import { randomBytes, randomUUID } from "node:crypto";
import { getPublicKey, hashes, sign } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { PrivateKey, Transaction } from "@hashgraph/sdk";
import { assertSoftwareKeysAllowed, WalletConfig } from "../config.js";
import { Vault } from "../vault/types.js";
import { KeyManager } from "./types.js";

if (!hashes.sha512) {
  hashes.sha512 = sha512;
}

const toBase64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");
const fromBase64 = (value: string) => new Uint8Array(Buffer.from(value, "base64"));

export const createSoftwareKeyManager = (input: {
  config: WalletConfig;
  vault: Vault;
}): KeyManager => {
  assertSoftwareKeysAllowed(input.config);

  return {
    async generateHolderKeypair() {
      const privateKey = new Uint8Array(randomBytes(32));
      const publicKey = await getPublicKey(privateKey);
      const id = randomUUID();
      const state = await input.vault.getState();
      state.holderKeys[id] = {
        privateKeyB64: toBase64(privateKey),
        publicKeyB64: toBase64(publicKey)
      };
      await input.vault.setState(state);
      return { id, type: "holder" };
    },
    async getHolderPublicJwk(keyRef) {
      const state = await input.vault.getState();
      const entry = state.holderKeys[keyRef.id];
      if (!entry) {
        throw new Error("holder_key_not_found");
      }
      return {
        kty: "OKP",
        crv: "Ed25519",
        x: Buffer.from(entry.publicKeyB64, "base64").toString("base64url"),
        alg: "EdDSA"
      };
    },
    async signWithHolderKey(keyRef, bytes) {
      const state = await input.vault.getState();
      const entry = state.holderKeys[keyRef.id];
      if (!entry) {
        throw new Error("holder_key_not_found");
      }
      const privateKey = fromBase64(entry.privateKeyB64);
      return sign(bytes, privateKey);
    },
    async importOrSetPayerKey(inputKey) {
      const id = randomUUID();
      const state = await input.vault.getState();
      state.payerKeys[id] = {
        accountId: inputKey.accountId,
        privateKey: inputKey.privateKey
      };
      await input.vault.setState(state);
      return { id, type: "payer" };
    },
    async getPayerAccountId(payerRef) {
      const state = await input.vault.getState();
      const entry = state.payerKeys[payerRef.id];
      if (!entry) {
        throw new Error("payer_key_not_found");
      }
      return entry.accountId;
    },
    async signHederaTx(payerRef, txBytes) {
      const state = await input.vault.getState();
      const entry = state.payerKeys[payerRef.id];
      if (!entry) {
        throw new Error("payer_key_not_found");
      }
      const tx = Transaction.fromBytes(txBytes);
      const signed = await tx.sign(PrivateKey.fromString(entry.privateKey));
      return signed.toBytes();
    }
  };
};
