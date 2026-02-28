# Contract E2E Suite (Gateway-only)

This suite validates contract-level invariants against a deployed staging stack on Hedera Testnet.
It uses **only** `APP_GATEWAY_BASE_URL` over HTTP(S) and performs real cryptographic operations.

## What it tests

- **Oracle-resistant verify responses**: consistent outward failure shape across failure classes.
- **Replay resistance**: reused challenges/nonce/audience are rejected.
- **Rotation/guardrails**: fail-fast startup for missing pepper, mainnet guard, service auth secrets.

## Run locally (contract suite)

```bash
RUN_TESTNET_INTEGRATION=1 \
HEDERA_NETWORK=testnet \
APP_GATEWAY_BASE_URL=https://staging-gateway.example \
pnpm -C apps/contract-e2e test:contract
```

### Required env

- `RUN_TESTNET_INTEGRATION=1` (suite refuses to run without it)
- `HEDERA_NETWORK=testnet`
- `APP_GATEWAY_BASE_URL` (public gateway URL)
- `CONTRACT_ONBOARDING_MODE` (must be `self-funded`; CUNCTA supports self-funded onboarding only)
- `CONTRACT_E2E_ADMIN_TOKEN` (must match gateway admin token for `/v1/onboard/revoke`)

For self-funded mode (required):

- `HEDERA_PAYER_ACCOUNT_ID`
- `HEDERA_PAYER_PRIVATE_KEY`
- `CONTRACT_TEST_DID` and `CONTRACT_TEST_HOLDER_JWK` (JSON)

### Optional env

- `CONTRACT_ACTION` (default: `identity.verify`)
- `CONTRACT_VCT` (default: `cuncta.age_over_18`)
- `CONTRACT_DEVICE_ID` (default: `contract-e2e-device`)
- `CONTRACT_HTTP_TIMEOUT_MS` (default: 15000)
- `CONTRACT_HTTP_RETRY_MAX` (default: 2; transport errors only)
- `CONTRACT_NONCE_EXPIRE_WAIT_MAX_MS` (default: 180000)
- `CONTRACT_REVOKE_WAIT_MAX_MS` (default: 180000)
- `CONTRACT_REVOKE_POLL_INTERVAL_MS` (default: 5000)
- `CONTRACT_TEST_DID` and `CONTRACT_TEST_HOLDER_JWK` (JSON) to reuse a DID + keypair

### Notes

- The gateway must allow onboarding for the selected `CONTRACT_VCT`
  (`GATEWAY_ALLOWED_VCTS` and `ISSUER_INTERNAL_ALLOWED_VCTS` on the staging stack).
- Gateway must be configured with `POLICY_SERVICE_BASE_URL` and `VERIFIER_SERVICE_BASE_URL`
  so `/v1/requirements` and `/v1/verify` are reachable.
- Gateway must enable contract admin routes (`CONTRACT_E2E_ENABLED=true`) and set
  `CONTRACT_E2E_ADMIN_TOKEN` to match this suite.
- The suite runs a preflight check (health + requirements + revoke capability) before expensive steps.
- The suite does **not** log raw credentials or JWTs; failure logs include only hashes.
- Retries only apply to transport-level failures (network/timeouts/5xx).

## Rotation/guard tests (local Docker)

These tests validate that services fail-fast in production configurations.
They run containers via `docker compose` and are intended for CI or a dev machine with Docker.

```bash
pnpm -C apps/contract-e2e test:guards
```

Expected failures:

- Missing `PSEUDONYMIZER_PEPPER` in production
- `HEDERA_NETWORK=mainnet` without `ALLOW_MAINNET=true`
- Missing `SERVICE_JWT_SECRET` in production (gateway)

## CI guidance

- Run `test:contract` on a staging environment with real Testnet credentials.
- Run `test:guards` in a Docker-enabled CI job (or a documented local runbook).
