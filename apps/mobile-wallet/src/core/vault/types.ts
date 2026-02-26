export type DidRecord = {
  did: string;
  holderKeyRef: KeyRef;
  network: string;
  createdAt: string;
};

export type PayerRecord = {
  payerRef: PayerRef;
  accountId: string;
  network: string;
};

export type KeyRef = {
  id: string;
  type: "holder";
};

export type PayerRef = {
  id: string;
  type: "payer";
};

export type VaultState = {
  holderKeys: Record<string, { privateKeyB64: string; publicKeyB64: string }>;
  payerKeys: Record<string, { accountId: string; privateKey: string }>;
  credentials: Record<
    string,
    {
      id: string;
      network: string;
      issuerDid?: string;
      type?: string;
      vct?: string;
      sdJwt: string;
      storedAt: string;
    }
  >;
  relyingParties: Record<
    string,
    {
      aud: string;
      audHash: string;
      displayName?: string;
      firstSeenAt: string;
      lastSeenAt: string;
      policyHash?: string;
      pinnedPolicyHash?: string;
    }
  >;
  didRecord?: DidRecord;
  payerRecord?: PayerRecord;
};

export type Vault = {
  init(): Promise<void>;
  getState(): Promise<VaultState>;
  setState(state: VaultState): Promise<void>;
  wipe(): Promise<void>;
};
