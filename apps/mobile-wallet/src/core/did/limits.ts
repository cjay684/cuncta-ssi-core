export const deriveUserPaysLimits = (input: {
  walletMaxFeeTinybars: number;
  gatewayMaxFeeTinybars?: number;
  gatewayMaxTxBytes?: number;
  gatewayRequestTtlSeconds?: number;
  requestExpiresAt: string;
  nowMs: number;
  skewMs?: number;
}) => {
  if (!Number.isFinite(input.walletMaxFeeTinybars) || input.walletMaxFeeTinybars <= 0) {
    throw new Error("max_fee_invalid");
  }
  const effectiveMaxFee =
    input.gatewayMaxFeeTinybars === undefined
      ? input.walletMaxFeeTinybars
      : Math.min(input.walletMaxFeeTinybars, input.gatewayMaxFeeTinybars);
  if (!Number.isFinite(effectiveMaxFee) || effectiveMaxFee <= 0) {
    throw new Error("effective_max_fee_invalid");
  }

  const expiresAtMs = Date.parse(input.requestExpiresAt);
  if (Number.isNaN(expiresAtMs)) {
    throw new Error("request_expiry_invalid");
  }
  const skewMs = input.skewMs ?? 4000;
  if (input.nowMs > expiresAtMs - skewMs) {
    throw new Error("request_expired");
  }

  return {
    effectiveMaxFeeTinybars: effectiveMaxFee,
    gatewayMaxTxBytes: input.gatewayMaxTxBytes,
    expiresAtMs,
    effectiveExpiryMs: expiresAtMs - skewMs,
    requestTtlSeconds:
      input.gatewayRequestTtlSeconds !== undefined && input.gatewayRequestTtlSeconds > 0
        ? input.gatewayRequestTtlSeconds
        : undefined
  };
};
