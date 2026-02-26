import { hashCanonicalJson } from "@cuncta/shared";

const TOKEN_ID_REGEX = /^0\.0\.\d+$/;
const ACCOUNT_ID_REGEX = /^0\.0\.\d+$/;
const AMOUNT_REGEX = /^(?:0|[1-9]\d*)(?:\.\d+)?$/;

export type AssetRef =
  | {
      kind: "HBAR";
      symbol?: string;
      decimals?: number;
    }
  | {
      kind: "HTS";
      tokenId: string;
      symbol?: string;
      decimals?: number;
    };

export type FeeLineItem = {
  asset: AssetRef;
  amount: string;
  purpose: string;
  memoHint?: string;
};

export type FeeQuote = {
  items: FeeLineItem[];
  totalByAsset: Record<string, string>;
  quoteFingerprint: string;
};

export type HederaAccountRef = {
  kind: "HEDERA_ACCOUNT";
  accountId: string;
  network: "testnet" | "mainnet";
};

export type PaymentInstruction = {
  asset: AssetRef;
  amount: string;
  to: HederaAccountRef;
  memo: string;
  purpose: string;
};

export type PaymentRequest = {
  instructions: PaymentInstruction[];
  paymentRef: string;
  paymentRequestFingerprint: string;
  note?: string;
};

type RawSchedule = {
  version?: unknown;
  assets?: Record<string, unknown>;
  fees?: Record<string, unknown>;
};

type RawAsset = {
  kind?: unknown;
  symbol?: unknown;
  decimals?: unknown;
  tokenId_testnet?: unknown;
  tokenId_mainnet?: unknown;
};

type RawFeeEntry = {
  asset?: unknown;
  amount?: unknown;
  purpose?: unknown;
  memoHint?: unknown;
};

type RuntimeSchedule = {
  version: number;
  actionFees: Record<string, FeeLineItem[]>;
  intentFees: Record<string, FeeLineItem[]>;
  purposeFees: Record<string, FeeLineItem[]>;
};

export type ParsedFeeSchedule = {
  schedule: RuntimeSchedule;
  scheduleFingerprint: string;
};

const isDecimalString = (value: string) => AMOUNT_REGEX.test(value);

const parseDecimals = (value: unknown, fallback: number) => {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 18) {
    throw new Error("invalid_decimals");
  }
  return value;
};

const validateAssetRef = (asset: AssetRef) => {
  if (asset.kind === "HTS" && !TOKEN_ID_REGEX.test(asset.tokenId)) {
    throw new Error("invalid_token_id");
  }
  if (asset.decimals !== undefined) {
    parseDecimals(asset.decimals, 0);
  }
};

const normalizeAssetRef = (asset: AssetRef): AssetRef => {
  validateAssetRef(asset);
  if (asset.kind === "HBAR") {
    return {
      kind: "HBAR",
      symbol: asset.symbol?.trim() || undefined,
      decimals: parseDecimals(asset.decimals, 8)
    };
  }
  return {
    kind: "HTS",
    tokenId: asset.tokenId,
    symbol: asset.symbol?.trim() || undefined,
    decimals: parseDecimals(asset.decimals, 0)
  };
};

const parseUnits = (amount: string, decimals: number) => {
  if (!isDecimalString(amount)) throw new Error("invalid_amount");
  const [wholePart, fractionalPart = ""] = amount.split(".");
  if (fractionalPart.length > decimals) throw new Error("amount_precision_exceeds_decimals");
  const wholeUnits = BigInt(wholePart) * 10n ** BigInt(decimals);
  const paddedFraction = `${fractionalPart}${"0".repeat(decimals - fractionalPart.length)}`;
  const fractionalUnits = paddedFraction.length > 0 ? BigInt(paddedFraction) : 0n;
  return wholeUnits + fractionalUnits;
};

const formatUnits = (units: bigint, decimals: number) => {
  if (decimals === 0) return units.toString();
  const divisor = 10n ** BigInt(decimals);
  const whole = units / divisor;
  const fraction = (units % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction.length > 0 ? `${whole.toString()}.${fraction}` : whole.toString();
};

const feeAssetKey = (asset: AssetRef) => (asset.kind === "HBAR" ? "HBAR" : `HTS:${asset.tokenId}`);

const sortFeeItems = (items: FeeLineItem[]) =>
  [...items].sort((a, b) => {
    const aTokenId = a.asset.kind === "HTS" ? a.asset.tokenId : "";
    const bTokenId = b.asset.kind === "HTS" ? b.asset.tokenId : "";
    const aDecimals = a.asset.decimals ?? 0;
    const bDecimals = b.asset.decimals ?? 0;
    return (
      a.asset.kind.localeCompare(b.asset.kind) ||
      aTokenId.localeCompare(bTokenId) ||
      a.purpose.localeCompare(b.purpose) ||
      a.amount.localeCompare(b.amount) ||
      aDecimals - bDecimals
    );
  });

const normalizeFeeItems = (items: FeeLineItem[]) =>
  sortFeeItems(
    items.map((item) => {
      const amount = item.amount.trim();
      if (!isDecimalString(amount)) throw new Error("invalid_amount");
      const purpose = item.purpose.trim();
      if (!purpose) throw new Error("invalid_purpose");
      const asset = normalizeAssetRef(item.asset);
      parseUnits(amount, asset.decimals ?? 0);
      return {
        asset,
        amount,
        purpose,
        memoHint: item.memoHint?.trim() || undefined
      };
    })
  );

const sortPaymentInstructions = (instructions: PaymentInstruction[]) =>
  [...instructions].sort((a, b) => {
    const aTokenId = a.asset.kind === "HTS" ? a.asset.tokenId : "";
    const bTokenId = b.asset.kind === "HTS" ? b.asset.tokenId : "";
    return (
      a.asset.kind.localeCompare(b.asset.kind) ||
      aTokenId.localeCompare(bTokenId) ||
      a.purpose.localeCompare(b.purpose) ||
      a.amount.localeCompare(b.amount) ||
      a.to.accountId.localeCompare(b.to.accountId) ||
      a.memo.localeCompare(b.memo)
    );
  });

const truncateUtf8ToBytes = (value: string, maxBytes: number) => {
  if (Buffer.byteLength(value, "utf8") <= maxBytes) return value;
  let end = value.length;
  while (end > 0 && Buffer.byteLength(value.slice(0, end), "utf8") > maxBytes) {
    end -= 1;
  }
  return value.slice(0, end);
};

const sanitizeMemoPart = (value: string) => value.toLowerCase().replace(/[^a-z0-9._-]/g, "_");

const parseRawAsset = (asset: RawAsset, network: "testnet" | "previewnet" | "mainnet"): AssetRef => {
  if (asset.kind === "HBAR") {
    return normalizeAssetRef({
      kind: "HBAR",
      symbol: typeof asset.symbol === "string" ? asset.symbol : undefined,
      decimals: parseDecimals(asset.decimals, 8)
    });
  }
  if (asset.kind === "HTS") {
    const tokenIdField = network === "mainnet" ? asset.tokenId_mainnet : asset.tokenId_testnet;
    if (typeof tokenIdField !== "string") throw new Error("missing_token_id");
    return normalizeAssetRef({
      kind: "HTS",
      tokenId: tokenIdField,
      symbol: typeof asset.symbol === "string" ? asset.symbol : undefined,
      decimals: parseDecimals(asset.decimals, 0)
    });
  }
  throw new Error("invalid_asset_kind");
};

const parseScheduleEntryItems = (
  value: unknown,
  assetsByAlias: Record<string, AssetRef>
): FeeLineItem[] => {
  if (!Array.isArray(value)) throw new Error("invalid_fee_items");
  return normalizeFeeItems(
    value.map((row) => {
      const entry = row as RawFeeEntry;
      if (typeof entry.asset !== "string") throw new Error("invalid_fee_asset");
      const resolvedAsset = assetsByAlias[entry.asset];
      if (!resolvedAsset) throw new Error("unknown_asset_alias");
      if (typeof entry.amount !== "string") throw new Error("invalid_fee_amount");
      if (typeof entry.purpose !== "string") throw new Error("invalid_fee_purpose");
      return {
        asset: resolvedAsset,
        amount: entry.amount,
        purpose: entry.purpose,
        memoHint: typeof entry.memoHint === "string" ? entry.memoHint : undefined
      };
    })
  );
};

const normalizeSchedule = (schedule: RuntimeSchedule): RuntimeSchedule => {
  const sortedActionKeys = Object.keys(schedule.actionFees).sort();
  const sortedIntentKeys = Object.keys(schedule.intentFees).sort();
  const sortedPurposeKeys = Object.keys(schedule.purposeFees).sort();
  const actionFees: Record<string, FeeLineItem[]> = {};
  const intentFees: Record<string, FeeLineItem[]> = {};
  const purposeFees: Record<string, FeeLineItem[]> = {};
  for (const key of sortedActionKeys) actionFees[key] = normalizeFeeItems(schedule.actionFees[key] ?? []);
  for (const key of sortedIntentKeys) intentFees[key] = normalizeFeeItems(schedule.intentFees[key] ?? []);
  for (const key of sortedPurposeKeys) purposeFees[key] = normalizeFeeItems(schedule.purposeFees[key] ?? []);
  return {
    version: schedule.version,
    actionFees,
    intentFees,
    purposeFees
  };
};

export const parseFeeSchedule = (input: {
  scheduleJson: string;
  network: "testnet" | "previewnet" | "mainnet";
}): ParsedFeeSchedule => {
  if (!input.scheduleJson.trim()) {
    return {
      schedule: { version: 1, actionFees: {}, intentFees: {}, purposeFees: {} },
      scheduleFingerprint: hashCanonicalJson({ version: 1, assets: {}, fees: {} })
    };
  }
  const parsed = JSON.parse(input.scheduleJson) as RawSchedule;
  const version = parsed.version;
  if (typeof version !== "number" || !Number.isInteger(version) || version < 1) {
    throw new Error("invalid_schedule_version");
  }
  const rawAssets = parsed.assets ?? {};
  const assetsByAlias: Record<string, AssetRef> = {};
  for (const alias of Object.keys(rawAssets).sort()) {
    assetsByAlias[alias] = parseRawAsset(rawAssets[alias] as RawAsset, input.network);
  }
  const rawFees = parsed.fees ?? {};
  const actionFees: Record<string, FeeLineItem[]> = {};
  const intentFees: Record<string, FeeLineItem[]> = {};
  const purposeFees: Record<string, FeeLineItem[]> = {};
  for (const key of Object.keys(rawFees).sort()) {
    const items = parseScheduleEntryItems(rawFees[key], assetsByAlias);
    if (key.startsWith("action:")) {
      const actionKey = key.slice("action:".length).trim();
      if (!actionKey) throw new Error("invalid_action_key");
      actionFees[actionKey] = items;
      continue;
    }
    if (key.startsWith("intent:")) {
      const intentKey = key.slice("intent:".length).trim();
      if (!intentKey) throw new Error("invalid_intent_key");
      intentFees[intentKey] = items;
      continue;
    }
    if (key.startsWith("purpose:")) {
      const purposeKey = key.slice("purpose:".length).trim();
      if (!purposeKey) throw new Error("invalid_purpose_key");
      purposeFees[purposeKey] = items;
      continue;
    }
    throw new Error("invalid_fee_key");
  }
  const normalized = normalizeSchedule({ version, actionFees, intentFees, purposeFees });
  return {
    schedule: normalized,
    scheduleFingerprint: hashCanonicalJson({
      version: normalized.version,
      actionFees: Object.entries(normalized.actionFees),
      intentFees: Object.entries(normalized.intentFees),
      purposeFees: Object.entries(normalized.purposeFees)
    })
  };
};

export const buildFeeQuote = (items: FeeLineItem[]): FeeQuote => {
  const normalizedItems = normalizeFeeItems(items);
  const totals = new Map<string, { units: bigint; decimals: number }>();
  for (const item of normalizedItems) {
    const decimals = item.asset.decimals ?? 0;
    const key = feeAssetKey(item.asset);
    const existing = totals.get(key) ?? { units: 0n, decimals };
    const units = parseUnits(item.amount, decimals);
    totals.set(key, { units: existing.units + units, decimals });
  }
  const sortedTotals = [...totals.keys()].sort();
  const totalByAsset: Record<string, string> = {};
  for (const key of sortedTotals) {
    const entry = totals.get(key);
    if (!entry) continue;
    totalByAsset[key] = formatUnits(entry.units, entry.decimals);
  }
  const canonical = {
    items: normalizedItems.map((item) => ({
      asset: item.asset,
      amount: item.amount,
      purpose: item.purpose,
      memoHint: item.memoHint ?? null
    })),
    totals: sortedTotals.map((key) => [key, totalByAsset[key]])
  };
  return {
    items: normalizedItems,
    totalByAsset,
    quoteFingerprint: hashCanonicalJson(canonical)
  };
};

export const getFeeQuoteForContext = (input: {
  schedule: RuntimeSchedule;
  actionId: string | null;
  intent: string;
  purpose?: string | null;
}): FeeQuote | null => {
  const actionItems = input.actionId ? input.schedule.actionFees[input.actionId] : undefined;
  const intentItems = input.schedule.intentFees[input.intent];
  const purposeItems = input.purpose ? input.schedule.purposeFees[input.purpose] : undefined;
  const selected = actionItems ?? intentItems ?? purposeItems ?? [];
  if (selected.length === 0) return null;
  return buildFeeQuote(selected);
};

export const buildPaymentRequest = (input: {
  feeQuote: FeeQuote;
  feeScheduleFingerprint: string;
  purposeScope: string;
  receiver: HederaAccountRef;
  memoMaxBytes: number;
}): PaymentRequest => {
  if (!ACCOUNT_ID_REGEX.test(input.receiver.accountId)) {
    throw new Error("invalid_receiver_account_id");
  }
  if (!Number.isInteger(input.memoMaxBytes) || input.memoMaxBytes < 16 || input.memoMaxBytes > 256) {
    throw new Error("invalid_memo_max_bytes");
  }
  const purposeScope = input.purposeScope.trim();
  if (!purposeScope) {
    throw new Error("invalid_purpose_scope");
  }
  const paymentRef = hashCanonicalJson({
    feeQuoteFingerprint: input.feeQuote.quoteFingerprint,
    feeScheduleFingerprint: input.feeScheduleFingerprint,
    purposeScope
  });
  const ref8 = paymentRef.slice(0, 8);
  const memoBase = `cuncta:${sanitizeMemoPart(purposeScope).slice(0, 24)}:${ref8}`;
  const memo = truncateUtf8ToBytes(memoBase, input.memoMaxBytes);
  const instructions = sortPaymentInstructions(
    input.feeQuote.items.map((item) => ({
      asset: item.asset,
      amount: item.amount,
      to: input.receiver,
      memo,
      purpose: item.purpose
    }))
  );
  const canonical = {
    instructions: instructions.map((entry) => ({
      asset: entry.asset,
      amount: entry.amount,
      to: entry.to,
      memo: entry.memo,
      purpose: entry.purpose
    })),
    paymentRef,
    note: "advisory_only"
  };
  return {
    instructions,
    paymentRef,
    paymentRequestFingerprint: hashCanonicalJson(canonical),
    note: "advisory_only"
  };
};

export const getFeeQuoteForPlan = (input: {
  schedule: RuntimeSchedule;
  actionId: string | null;
  intent: string;
}): FeeQuote | null =>
  getFeeQuoteForContext({
    schedule: input.schedule,
    actionId: input.actionId,
    intent: input.intent,
    purpose: "command.plan"
  });
