const truthy = (value: string | undefined) => value === "true" || value === "1" || value === "yes";

const notEmpty = (value: string | undefined) => typeof value === "string" && value.trim().length > 0;

const failures: string[] = [];

const requireEq = (name: string, actual: string | undefined, expected: string) => {
  if ((actual ?? "").trim() !== expected) {
    failures.push(`${name} must be "${expected}" (got "${actual ?? ""}")`);
  }
};

const requireTruthy = (name: string, value: string | undefined) => {
  if (!truthy((value ?? "").trim())) {
    failures.push(`${name} must be truthy (true/1)`);
  }
};

const requirePresent = (name: string, value: string | undefined) => {
  if (!notEmpty(value)) {
    failures.push(`${name} must be set`);
  }
};

// Mainnet is an explicit, gated posture.
requireEq("HEDERA_NETWORK", process.env.HEDERA_NETWORK, "mainnet");
requireTruthy("ALLOW_MAINNET", process.env.ALLOW_MAINNET);

// Production posture expectations (config-only migration).
requireEq("NODE_ENV", process.env.NODE_ENV, "production");
if (truthy(process.env.BREAK_GLASS_DISABLE_STRICT)) {
  failures.push("BREAK_GLASS_DISABLE_STRICT must be false/off");
}

// OID4VCI (issuer) token signing: EdDSA only, production requires static key.
requirePresent("OID4VCI_TOKEN_SIGNING_JWK", process.env.OID4VCI_TOKEN_SIGNING_JWK);
if (truthy(process.env.OID4VCI_TOKEN_SIGNING_BOOTSTRAP)) {
  failures.push("OID4VCI_TOKEN_SIGNING_BOOTSTRAP must be false/off in production");
}
if (process.env.ISSUER_ENABLE_OID4VCI?.trim() === "false") {
  failures.push("ISSUER_ENABLE_OID4VCI must not be disabled on mainnet");
}

// OID4VP request signing (verifier): production requires static key.
if (process.env.VERIFIER_SIGN_OID4VP_REQUEST?.trim() === "false") {
  failures.push("VERIFIER_SIGN_OID4VP_REQUEST must not be disabled on mainnet");
}
requirePresent("VERIFIER_SIGNING_JWK", process.env.VERIFIER_SIGNING_JWK);
if (truthy(process.env.VERIFIER_SIGNING_BOOTSTRAP)) {
  failures.push("VERIFIER_SIGNING_BOOTSTRAP must be false/off in production");
}

// Gateway must attach signed request_jwt to the consumer /oid4vp/request surface.
requirePresent("APP_GATEWAY_PUBLIC_BASE_URL", process.env.APP_GATEWAY_PUBLIC_BASE_URL);
if (process.env.GATEWAY_SIGN_OID4VP_REQUEST?.trim() === "false") {
  failures.push("GATEWAY_SIGN_OID4VP_REQUEST must not be disabled on mainnet");
}

// Policy integrity signing: production requires static key (no bootstrap).
requirePresent("POLICY_SIGNING_JWK", process.env.POLICY_SIGNING_JWK);
if (truthy(process.env.POLICY_SIGNING_BOOTSTRAP)) {
  failures.push("POLICY_SIGNING_BOOTSTRAP must be false/off in production");
}

// Issuer key bootstraps must not run on mainnet production.
if (truthy(process.env.ISSUER_KEYS_BOOTSTRAP)) {
  failures.push("ISSUER_KEYS_BOOTSTRAP must be false/off in production");
}
if (truthy(process.env.ISSUER_KEYS_ALLOW_DB_PRIVATE)) {
  failures.push("ISSUER_KEYS_ALLOW_DB_PRIVATE must be false/off in production");
}

// Reconciliation: required for mainnet ops.
if (process.env.ANCHOR_RECONCILIATION_ENABLED?.trim() === "false") {
  failures.push("ANCHOR_RECONCILIATION_ENABLED must not be disabled on mainnet");
}

// Self-funded only.
if (truthy(process.env.ALLOW_SPONSORED_ONBOARDING)) {
  failures.push("ALLOW_SPONSORED_ONBOARDING must not be enabled (self-funded only)");
}
if ((process.env.ONBOARDING_STRATEGY_ALLOWED ?? "").toLowerCase().includes("sponsor")) {
  failures.push("ONBOARDING_STRATEGY_ALLOWED must not include sponsored");
}
if ((process.env.ONBOARDING_STRATEGY_DEFAULT ?? "").toLowerCase().includes("sponsor")) {
  failures.push("ONBOARDING_STRATEGY_DEFAULT must not be sponsored");
}

if (failures.length) {
  console.error("Mainnet readiness check FAILED:");
  for (const line of failures) {
    console.error(`- ${line}`);
  }
  process.exit(1);
}

console.log("Mainnet readiness check OK");

