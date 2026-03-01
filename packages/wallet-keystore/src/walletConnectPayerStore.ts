import { randomUUID } from "node:crypto";
import type { PayerKeyEntry, PayerKeyStore, PayerRef } from "./payerKeyStore.js";

type SignerDelegate = (input: {
  accountId: string;
  alg: PayerKeyEntry["alg"];
  txBytes: Uint8Array;
}) => Promise<Uint8Array>;

export const createWalletConnectPayerStore = (input: {
  signWithConnector: SignerDelegate;
}): PayerKeyStore => {
  const entries = new Map<string, PayerKeyEntry>();

  const resolveEntry = (ref: PayerRef) => {
    const entry = entries.get(ref.id);
    if (!entry) {
      throw new Error("payer_key_not_found");
    }
    return entry;
  };

  return {
    async addPayerKey(entry) {
      if (entry.source !== "walletconnect") {
        throw new Error("walletconnect_store_rejects_non_walletconnect_source");
      }
      const ref: PayerRef = { id: randomUUID(), type: "payer" };
      entries.set(ref.id, { ...entry });
      return ref;
    },
    async removePayerKey(ref) {
      entries.delete(ref.id);
    },
    async getPayerEntry(ref) {
      return entries.get(ref.id) ?? null;
    },
    async signTransaction(ref, txBytes) {
      const entry = resolveEntry(ref);
      return input.signWithConnector({
        accountId: entry.accountId,
        alg: entry.alg,
        txBytes
      });
    },
    async listPayerKeys() {
      return Array.from(entries.entries()).map(([id, entry]) => ({
        ref: { id, type: "payer" as const },
        entry: { ...entry }
      }));
    }
  };
};
