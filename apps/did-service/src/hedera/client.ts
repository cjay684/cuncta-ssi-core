import { config } from "../config.js";

export type HederaNetwork = "testnet" | "previewnet" | "mainnet";
export type RegistrarNetwork = "testnet" | "previewnet" | "mainnet";

export const buildRegistrarProviders = (network: HederaNetwork) => {
  const accountId =
    config.HEDERA_OPERATOR_ID_DID ??
    (config.ALLOW_LEGACY_OPERATOR_KEYS ? config.HEDERA_OPERATOR_ID : undefined);
  const privateKey =
    config.HEDERA_OPERATOR_PRIVATE_KEY_DID ??
    (config.ALLOW_LEGACY_OPERATOR_KEYS ? config.HEDERA_OPERATOR_PRIVATE_KEY : undefined);
  if (!accountId || !privateKey) {
    throw new Error("Hedera operator is not configured.");
  }
  return {
    clientOptions: {
      network: network as unknown as string,
      accountId,
      privateKey
    }
  };
};

export const assertOperatorConfigured = () => {
  const accountId =
    config.HEDERA_OPERATOR_ID_DID ??
    (config.ALLOW_LEGACY_OPERATOR_KEYS ? config.HEDERA_OPERATOR_ID : undefined);
  const privateKey =
    config.HEDERA_OPERATOR_PRIVATE_KEY_DID ??
    (config.ALLOW_LEGACY_OPERATOR_KEYS ? config.HEDERA_OPERATOR_PRIVATE_KEY : undefined);
  if (!accountId || !privateKey) {
    throw new Error("Hedera operator is not configured.");
  }
};
