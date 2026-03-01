export type WalletEd25519Keypair = {
  // base64 (standard, not base64url) for compact filesystem storage
  privateKeyBase64: string;
  publicKeyBase64: string;
  // multibase (base58btc) public key, used by did-service onboarding APIs
  publicKeyMultibase?: string;
};

export type WalletDidRecord = {
  did: string;
  topicId?: string;
  transactionId?: string;
};

export type WalletCredentialValue = string | Record<string, unknown>;

export type WalletCredentialRecord = {
  vct: string;
  // sd-jwt-vc compact string (sd-jwt + disclosures + trailing "~")
  // DI+BBS credentials can be JSON objects (dev/test artifact).
  credential: WalletCredentialValue;
  // Legacy wallet-cli used `sdJwt` in some commands; keep for backwards compatibility.
  sdJwt?: WalletCredentialValue;
  credentialId?: string;
  // optional metadata for debugging/auditing in tests
  eventId?: string;
  credentialFingerprint?: string;
  // Preserve forward-compatible metadata without breaking parsing/serialization in tests.
  [key: string]: unknown;
};

export type WalletKeysState = {
  ed25519?: WalletEd25519Keypair;
  holder?: {
    alg: "Ed25519";
    publicKeyBase64: string;
    publicKeyMultibase: string;
  };
  [key: string]: unknown;
};

export type WalletState = {
  keys?: WalletKeysState;
  did?: WalletDidRecord;
  credentials?: WalletCredentialRecord[];
  lastPresentation?: {
    action: string;
    presentation: string;
    nonce: string;
    audience: string;
  };
  [key: string]: unknown;
};
