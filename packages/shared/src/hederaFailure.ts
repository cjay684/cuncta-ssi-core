export type HederaFailureKind = "transient" | "deterministic" | "unknown";

export type HederaFailureClassification = {
  kind: HederaFailureKind;
  code?: string;
  status?: string;
  txId?: string;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

// Hedera tx ids often appear as: 0.0.1234@1700000000.123456789
const TX_ID_RE = /\b\d+\.\d+\.\d+@\d+\.\d+\b/;

export const extractTxIdFromError = (error: unknown): string | undefined => {
  if (!error) return undefined;
  if (isRecord(error) && typeof error.transactionId === "string") {
    return error.transactionId;
  }
  const message =
    error instanceof Error
      ? error.message
      : isRecord(error) && typeof error.message === "string"
        ? error.message
        : undefined;
  if (!message) return undefined;
  const match = message.match(TX_ID_RE);
  return match?.[0];
};

export const extractHederaStatusFromError = (error: unknown): string | undefined => {
  if (!error) return undefined;
  if (isRecord(error) && typeof error.status === "string") {
    return error.status;
  }
  // Some SDK errors nest status under a receipt or similar structure.
  if (isRecord(error) && isRecord(error.receipt) && typeof error.receipt.status === "string") {
    return error.receipt.status;
  }
  const message =
    error instanceof Error
      ? error.message
      : isRecord(error) && typeof error.message === "string"
        ? error.message
        : undefined;
  if (!message) return undefined;
  // Example: "receipt for transaction ... contained error status FAIL_INVALID"
  const m = message.match(/\bstatus\s+([A-Z0-9_]+)\b/);
  return m?.[1];
};

const isAbortLike = (error: unknown) => {
  if (!error) return false;
  if (error instanceof DOMException && error.name === "AbortError") return true;
  if (error instanceof Error && error.name === "AbortError") return true;
  const msg = error instanceof Error ? error.message : isRecord(error) ? String(error.message ?? "") : "";
  return /abort|aborted|timeout|timed out/i.test(msg);
};

export const classifyHederaFailure = (error: unknown): HederaFailureClassification => {
  const txId = extractTxIdFromError(error);
  const status = extractHederaStatusFromError(error);
  const code =
    error instanceof Error
      ? (error as unknown as { code?: string }).code
      : isRecord(error) && typeof error.code === "string"
        ? error.code
        : undefined;

  // Explicit abort/timeout/network-ish errors are typically transient.
  if (isAbortLike(error)) {
    return { kind: "transient", code: code ?? "timeout", status, txId };
  }

  // A conservative status-based classifier:
  // - deterministic: cryptographic/format/auth failures that will not change on retry
  // - transient: platform/network availability conditions
  // - unknown: ambiguous (retryable, but bounded)
  if (status) {
    const deterministic = new Set([
      "INVALID_SIGNATURE",
      "INVALID_TRANSACTION",
      "INVALID_TRANSACTION_BODY",
      "INVALID_ACCOUNT_ID",
      "ACCOUNT_ID_DOES_NOT_EXIST",
      "PAYER_ACCOUNT_NOT_FOUND",
      "INVALID_PAYER_SIGNATURE",
      "UNAUTHORIZED",
      "KEY_REQUIRED",
      "BAD_ENCODING",
      "INVALID_FILE_ID",
      "INVALID_TOPIC_ID"
    ]);
    if (deterministic.has(status)) {
      return { kind: "deterministic", code: code ?? status, status, txId };
    }

    const transient = new Set([
      "BUSY",
      "PLATFORM_NOT_ACTIVE",
      "PLATFORM_TRANSACTION_NOT_CREATED",
      "RECEIPT_NOT_FOUND",
      "RECORD_NOT_FOUND"
    ]);
    if (transient.has(status)) {
      return { kind: "transient", code: code ?? status, status, txId };
    }

    // FAIL_INVALID has shown up as a real-world intermittent receipt status; treat as ambiguous.
    if (status === "FAIL_INVALID") {
      return { kind: "unknown", code: code ?? status, status, txId };
    }

    // Anything else is ambiguous (bounded retries only).
    return { kind: "unknown", code: code ?? status, status, txId };
  }

  // If we don't have a status, classify by error name/message conservatively.
  const name =
    error instanceof Error
      ? error.name
      : isRecord(error) && typeof error.name === "string"
        ? error.name
        : undefined;
  if (name && /receipt|mirror|network|timeout/i.test(name)) {
    return { kind: "transient", code: code ?? name, status, txId };
  }

  return { kind: "unknown", code, status, txId };
};

