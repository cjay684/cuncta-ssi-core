import type { KeyRef, PayerRef } from "../vault/types.js";

export type KeyManager = {
  generateHolderKeypair(): Promise<KeyRef>;
  getHolderPublicJwk(keyRef: KeyRef): Promise<Record<string, unknown>>;
  signWithHolderKey(keyRef: KeyRef, bytes: Uint8Array): Promise<Uint8Array>;
  importOrSetPayerKey(input: { accountId: string; privateKey: string }): Promise<PayerRef>;
  getPayerAccountId(payerRef: PayerRef): Promise<string>;
  signHederaTx(payerRef: PayerRef, txBytes: Uint8Array): Promise<Uint8Array>;
};
