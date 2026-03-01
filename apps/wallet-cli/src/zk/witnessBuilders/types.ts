export type WalletZkWitnessBuilder = (input: {
  // Registry-driven, statement-scoped inputs
  statementId: string;
  circuitId: string;
  params: Record<string, unknown>;
  zkContext: Record<string, unknown>;
  bindings: { nonce: string; audience: string; requestHash: string };

  // Disclosed credential values (e.g., SD-JWT disclosures)
  disclosedClaims: Record<string, unknown>;

  // Wallet-local secret material (never leaves the device)
  secrets: Record<string, unknown>;
}) => Promise<Record<string, string>>;
