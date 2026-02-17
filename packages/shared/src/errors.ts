export type ErrorCode =
  | "invalid_request"
  | "not_found"
  | "forbidden"
  | "service_auth_not_configured"
  | "service_auth_unavailable"
  | "service_auth_scope_missing"
  | "policy_not_found"
  | "policy_integrity_failed"
  | "requirements_unavailable"
  | "resolver_unavailable"
  | "catalog_integrity_failed"
  | "challenge_invalid"
  | "challenge_expired"
  | "challenge_consumed"
  | "issuer_not_allowed"
  | "credential_revoked"
  | "disclosure_missing"
  | "binding_invalid"
  | "aura_not_ready"
  | "rate_limited"
  | "sponsor_budget_exceeded"
  | "sponsor_budget_unavailable"
  | "sponsor_kill_switch"
  | "self_funded_onboarding_disabled"
  | "self_funded_submit_failed"
  | "aura_integrity_failed"
  | "sponsored_onboarding_disabled"
  | "maintenance_mode"
  | "privacy_erased"
  | "policy_pack_hash_mismatch"
  | "internal_error";

export type ErrorResponse = {
  error: ErrorCode;
  message: string;
  details?: string;
  debug?: { cause?: string; hint?: string };
};

type ErrorOptions = {
  details?: string;
  debug?: { cause?: string; hint?: string };
  devMode?: boolean;
};

export const makeErrorResponse = (
  error: ErrorCode,
  message: string,
  options: ErrorOptions = {}
): ErrorResponse => {
  const response: ErrorResponse = { error, message };
  if (options.details) {
    response.details = options.details;
  }
  if (options.devMode && options.debug) {
    response.debug = options.debug;
  }
  return response;
};
