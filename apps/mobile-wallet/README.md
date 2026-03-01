# Mobile Wallet (Sprint 1 scaffold)

Minimal, stack-agnostic wallet skeleton that performs **gateway-only** self-funded DID onboarding.
This is a developer scaffold intended to be wrapped by a mobile UI framework later.

## What it does (Sprint 1)

- Loads config and shows network banner.
- Generates holder keypair (software keys, **dev-only** guard).
- Stores payer key locally.
- Calls gateway `/v1/capabilities`.
- Creates a DID via gateway user-pays (request → local sign/build → submit).
- Polls **gateway resolve** until DID appears.
- Persists DID + key references in an encrypted vault.
- Supports wipe.

## Run (developer shell)

```bash
pnpm -C apps/mobile-wallet dev
```

## Sprint 2 commands (verification)

```bash
# Import a pre-issued SD-JWT credential (no logging of raw contents)
WALLET_SD_JWT=... pnpm -C apps/mobile-wallet credential:import

# List credentials (metadata only)
pnpm -C apps/mobile-wallet credential:list

# Verify against gateway (uses first requirement; requires prior DID create)
WALLET_CREDENTIAL_ID=... WALLET_VERIFY_ACTION=identity.verify pnpm -C apps/mobile-wallet verify

# Optional end-to-end smoke (requires pre-issued credential + DID)
WALLET_SD_JWT=... WALLET_VERIFY_ACTION=identity.verify pnpm -C apps/mobile-wallet verify:smoke

# Selective disclosure (manual selection via env)
WALLET_CREDENTIAL_ID=... WALLET_DISCLOSE=age,email WALLET_CONFIRM=true pnpm -C apps/mobile-wallet verify:selective
```

## Required env

- `APP_GATEWAY_BASE_URL`
- `HEDERA_NETWORK=testnet`
- `WALLET_ALLOW_SOFTWARE_KEYS=true` (dev-only guard)
- `WALLET_VAULT_KEY` (base64url or hex, 32 bytes)
- `HEDERA_PAYER_ACCOUNT_ID`
- `HEDERA_PAYER_PRIVATE_KEY`

Optional:

- `USER_PAYS_MAX_FEE_TINYBARS` (default 50_000_000)
- `WALLET_DEVICE_ID` (default `mobile-wallet-device`)
- `WALLET_BUILD_MODE` (`development` or `production`)
- `ALLOW_MAINNET=true` (required when `HEDERA_NETWORK=mainnet`)
- `WALLET_VERIFY_ACTION` (default `identity.verify`)
- `WALLET_CREDENTIAL_ID` (required for `verify`)
- `WALLET_SD_JWT` (required for `credential:import`)
- `WALLET_DISCLOSE` (comma-separated claim names or ids for `verify:selective`)
- `WALLET_CONFIRM=true` (required on first-seen or policy-hash change)

## Sprint 1 runbook (manual)

1. Set env vars above (Testnet payer required).
2. Run `pnpm -C apps/mobile-wallet dev`.
3. Expect logs:
   - capabilities probe
   - DID create submit
   - DID resolved ✅
4. Verify vault file is encrypted (not plaintext JSON).
5. Trigger wipe (`pnpm -C apps/mobile-wallet wipe`) and verify vault file is cleared.

Sprint 1 is complete when `pnpm -C apps/mobile-wallet test` passes in an environment with deps
installed and a manual Testnet DID create+resolve run succeeds against staging.

## Integration check (optional)

```bash
APP_GATEWAY_BASE_URL=https://staging-gateway.example pnpm -C apps/mobile-wallet test:capabilities
```

## Sprint 1 unit checks

```bash
pnpm -C apps/mobile-wallet test
```

## Notes

- Software keys are **dev-only** and hard-fail in production mode.
- This scaffold reuses the wallet-cli flow for DIDOwnerMessage + TopicMessageSubmitTransaction.
- The wallet caps fee/size/TTL using gateway capabilities when provided.
- Selective disclosure UX is minimal/default in Sprint 2 (full UX planned later).
- `WALLET_VERIFY_ACTION` must exist in policy-service or verification will deny.
