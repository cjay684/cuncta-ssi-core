import { Hbar, TopicMessageSubmitTransaction, Transaction } from "@hashgraph/sdk";
import { z } from "zod";

export type TxBudget = {
  maxFeeTinybars: number;
  maxTxBytes: number;
};

export type FeeBudgets = {
  TopicMessageSubmitTransaction: TxBudget;
};

const TxBudgetSchema = z.object({
  maxFeeTinybars: z.number().int().min(1).max(1_000_000_000),
  maxTxBytes: z.number().int().min(1024).max(256 * 1024)
});

const FeeBudgetsSchema = z.object({
  TopicMessageSubmitTransaction: TxBudgetSchema
});

export const defaultFeeBudgets = (input: {
  userPaysMaxFeeTinybars: number;
  userPaysMaxTxBytes: number;
}): FeeBudgets => ({
  TopicMessageSubmitTransaction: {
    maxFeeTinybars: input.userPaysMaxFeeTinybars,
    maxTxBytes: input.userPaysMaxTxBytes
  }
});

export const parseFeeBudgetsJson = (raw: string | undefined, fallback: FeeBudgets): FeeBudgets => {
  const text = String(raw ?? "").trim();
  if (!text) return fallback;
  try {
    return FeeBudgetsSchema.parse(JSON.parse(text) as unknown);
  } catch {
    return fallback;
  }
};

const toTinybarsNumber = (value: unknown): number | null => {
  if (value === undefined || value === null) return null;
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  if (typeof value === "object" && typeof (value as { toNumber?: unknown }).toNumber === "function") {
    return (value as { toNumber: () => number }).toNumber();
  }
  return null;
};

export const extractMaxFeeTinybars = (tx: Transaction): number | null => {
  // @hashgraph/sdk stores maxTransactionFee as Hbar-like.
  const raw = (tx as unknown as { maxTransactionFee?: unknown }).maxTransactionFee;
  if (!raw) return null;
  const tinybars = (raw as { toTinybars?: () => unknown }).toTinybars?.();
  return toTinybarsNumber(tinybars);
};

export const enforceSignedTopicMessageSubmitBudget = (input: {
  signedTransactionBytes: Uint8Array;
  budget: TxBudget;
}):
  | { ok: true; tx: TopicMessageSubmitTransaction; maxFeeTinybars: number | null }
  | { ok: false; reason: "signed_tx_too_large" | "tx_type_not_allowed" | "max_fee_too_high" } => {
  if (input.signedTransactionBytes.length > input.budget.maxTxBytes) {
    return { ok: false, reason: "signed_tx_too_large" };
  }
  const tx = Transaction.fromBytes(input.signedTransactionBytes);
  if (!(tx instanceof TopicMessageSubmitTransaction)) {
    return { ok: false, reason: "tx_type_not_allowed" };
  }
  const maxFee = extractMaxFeeTinybars(tx);
  if (maxFee !== null && maxFee > input.budget.maxFeeTinybars) {
    return { ok: false, reason: "max_fee_too_high" };
  }
  return { ok: true, tx, maxFeeTinybars: maxFee };
};

export const applyTopicSubmitMaxFee = (tx: TopicMessageSubmitTransaction, maxFeeTinybars: number) => {
  return tx.setMaxTransactionFee(Hbar.fromTinybars(maxFeeTinybars));
};

