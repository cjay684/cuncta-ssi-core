import type { KeyManager } from "../keys/types.js";
import { queryPayerBalance } from "./balanceQuery.js";

type ResolvedPayer = {
  accountId: string;
  privateKey: string;
  source: "testnet_payer" | "hedera_payer";
};

export type PayerSetupResult = {
  payerRef: { id: string; type: "payer" };
  accountId: string;
  balanceTinybars: number;
};

const resolvePayerCredentials = (): ResolvedPayer => {
  const testnetAccountId = process.env.TESTNET_PAYER_ACCOUNT_ID?.trim();
  const testnetPrivateKey = process.env.TESTNET_PAYER_PRIVATE_KEY?.trim();
  if (testnetAccountId && testnetPrivateKey) {
    return {
      accountId: testnetAccountId,
      privateKey: testnetPrivateKey,
      source: "testnet_payer"
    };
  }
  const accountId = process.env.HEDERA_PAYER_ACCOUNT_ID?.trim();
  const privateKey = process.env.HEDERA_PAYER_PRIVATE_KEY?.trim();
  if (accountId && privateKey) {
    return {
      accountId,
      privateKey,
      source: "hedera_payer"
    };
  }
  throw new Error("missing_payer_credentials");
};

export const createPayerManager = (input: { keyManager: KeyManager }) => {
  return {
    async importFromEnvironmentAndQueryBalance(): Promise<PayerSetupResult> {
      const payer = resolvePayerCredentials();
      const payerRef = await input.keyManager.importOrSetPayerKey({
        accountId: payer.accountId,
        privateKey: payer.privateKey
      });
      const balance = await queryPayerBalance(payer.accountId);
      console.log(`[wallet] payer_source=${payer.source} account=${payer.accountId}`);
      return {
        payerRef,
        accountId: payer.accountId,
        balanceTinybars: balance.tinybars
      };
    }
  };
};
