# Hedera Testnet E2E (Real Network, No Mocks)

This repo includes an opt-in integration harness that runs against:

- Real Hedera **testnet** (HCS submits + mirror resolution)
- Local services + local Postgres
- Real `wallet-cli` commands (OID4VCI acquire + OID4VP respond)

The harness is the canonical “local Testnet E2E” proof.

## Preconditions

- Node `>=20`
- `pnpm install`
- Postgres reachable via `DATABASE_URL`
- A funded Hedera testnet operator account:
  - `HEDERA_OPERATOR_ID=0.0.xxxxx`
  - `HEDERA_OPERATOR_PRIVATE_KEY=...`

Notes:

- Testnet costs HBAR (testnet faucet).
- The harness can use the operator account as payer **only on testnet/dev**.

## Required environment variables

The harness validates required envs at startup.

Minimum set:

- `HEDERA_NETWORK=testnet`
- `HEDERA_OPERATOR_ID`
- `HEDERA_OPERATOR_PRIVATE_KEY`
- `DATABASE_URL`
- `PSEUDONYMIZER_PEPPER`
- `SERVICE_JWT_SECRET`

Service URLs (if you are not using dynamic ports):

- `DID_SERVICE_BASE_URL` (default: `http://localhost:3001`)
- `ISSUER_SERVICE_BASE_URL` (default: `http://localhost:3002`)
- `VERIFIER_SERVICE_BASE_URL` (default: `http://localhost:3003`)
- `POLICY_SERVICE_BASE_URL` (default: `http://localhost:3004`)
- `APP_GATEWAY_BASE_URL` (default: `http://localhost:3010`, only needed when `GATEWAY_MODE=1`)

Recommended:

- `ALLOW_MAINNET=false`
- `GATEWAY_MODE=1` (exercises the real customer posture: gateway as consumer surface)

## Run (canonical: gateway mode)

PowerShell:

```powershell
$env:HEDERA_NETWORK="testnet"
$env:ALLOW_MAINNET="false"
$env:GATEWAY_MODE="1"
pnpm verify:testnet
```

This runs:

- `cross-env RUN_TESTNET_INTEGRATION=1 pnpm -C apps/integration-tests test:integration`

## What “success” looks like

The harness prints `Integration tests complete.` when it finishes.

It exercises (real network):

- Self-funded-only posture: legacy sponsored onboarding returns `410` with `sponsored_onboarding_not_supported`
- DID creation and resolution (did:hedera on testnet)
- OID4VCI token issuance + credential issuance (EdDSA access tokens)
- OID4VP request signing (gateway attaches `request_jwt`) + wallet signature verification
- Strict posture assertions (origin-scoped audiences; unsigned request rejected by wallet)
- Revocation -> verification `DENY`
- Anchor worker receipts + reconciliation ops endpoint smoke

## Common failures (actionable triage)

1. `HEDERA_NETWORK must be set to testnet`

- Fix: set `HEDERA_NETWORK=testnet` explicitly.

2. `Missing required env vars: ...`

- Fix: provide the required env vars listed by the error.

3. Hedera flakiness (receipt / network / mirror lag)

- The harness includes bounded retries/backoff for transient Hedera failures and bounded polling for DID visibility.
- If failures persist, verify:
  - operator account is funded
  - `MIRROR_NODE_BASE_URL` is reachable if overridden
  - local clock skew is not extreme

4. `service_auth_not_configured`

- Fix: set `SERVICE_JWT_SECRET` (and optionally `SERVICE_JWT_SECRET_*`) in your env for local runs.
