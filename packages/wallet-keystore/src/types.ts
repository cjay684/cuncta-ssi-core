// Purposes:
// - primary: DID root key (used to sign DID update/deactivate operations).
// - holder: holder binding key (used for kb-jwt, OID4VP responses, etc).
// - recovery: dedicated recovery key for account recovery flows.
export type WalletKeyPurpose = "primary" | "holder" | "recovery";

export type WalletKeyAlg = "Ed25519";

export type WalletPublicKeyMaterial = {
  purpose: WalletKeyPurpose;
  alg: WalletKeyAlg;
  publicKey: Uint8Array;
  publicKeyMultibase: string;
};

export type WalletKeyStore = {
  // Returns existing key if present, otherwise generates + persists it.
  // MUST NOT return exportable private key material.
  ensureKey(purpose: WalletKeyPurpose): Promise<WalletPublicKeyMaterial>;
  // Loads an existing key; returns null if missing. MUST NOT return private key material.
  loadKey(purpose: WalletKeyPurpose): Promise<WalletPublicKeyMaterial | null>;
  // Signs bytes with the purpose key (holder binding, DID ops).
  sign(purpose: WalletKeyPurpose, payload: Uint8Array): Promise<Uint8Array>;
  // Optional: overwrite/import a key (used for rotation/migration).
  // Implementations MUST persist without writing raw private key material to disk in plaintext.
  saveKeyMaterial?: (key: {
    purpose: WalletKeyPurpose;
    alg: WalletKeyAlg;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
    publicKeyMultibase?: string;
  }) => Promise<void>;
  // Deletes a key (used for "lost primary" simulations / resets).
  deleteKey(purpose: WalletKeyPurpose): Promise<void>;
};
