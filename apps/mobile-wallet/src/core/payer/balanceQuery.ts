export type PayerBalance = {
  accountId: string;
  tinybars: number;
};

const toMirrorBaseUrl = () => {
  const fromEnv = process.env.HEDERA_MIRROR_URL?.trim();
  return fromEnv && fromEnv.length > 0 ? fromEnv : "https://testnet.mirrornode.hedera.com";
};

export const queryPayerBalance = async (accountId: string): Promise<PayerBalance> => {
  const base = toMirrorBaseUrl();
  const url = new URL("/api/v1/balances", base);
  url.searchParams.set("account.id", accountId);
  const response = await fetch(url.toString());
  if (!response.ok) {
    throw new Error(`payer_balance_query_failed:${response.status}`);
  }
  const payload = (await response.json()) as {
    balances?: Array<{ account?: string; balance?: number | string }>;
  };
  const entry = (payload.balances ?? []).find((item) => String(item.account ?? "") === accountId);
  const tinybars = Number(entry?.balance ?? NaN);
  if (!Number.isFinite(tinybars)) {
    throw new Error("payer_balance_parse_failed");
  }
  return { accountId, tinybars };
};
