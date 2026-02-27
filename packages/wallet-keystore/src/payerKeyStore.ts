export type PayerKeyAlg = "Ed25519" | "ECDSA_SECP256K1";

export type PayerKeySource = "imported" | "walletconnect";

export type PayerRef = {
  id: string;
  type: "payer";
};

export type PayerKeyEntry = {
  accountId: string;
  alg: PayerKeyAlg;
  source: PayerKeySource;
  publicKeyDer?: string;
};

export type PayerKeyStore = {
  addPayerKey(entry: PayerKeyEntry, privateKeyBytes?: Uint8Array): Promise<PayerRef>;
  removePayerKey(ref: PayerRef): Promise<void>;
  getPayerEntry(ref: PayerRef): Promise<PayerKeyEntry | null>;
  signTransaction(ref: PayerRef, txBytes: Uint8Array): Promise<Uint8Array>;
  listPayerKeys(): Promise<Array<{ ref: PayerRef; entry: PayerKeyEntry }>>;
};
