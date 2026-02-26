# Contributing

Thanks for helping improve CUNCTA SSI Core. This repo is Testnet-only and emphasizes real integration tests.

## Setup

1. Install Node.js (>=20) and pnpm (`corepack enable`).
2. Install deps:
   ```bash
   pnpm install
   ```

## Run unit CI locally

```bash
pnpm format:check
pnpm lint
pnpm -r build
pnpm -r typecheck
pnpm -r test
pnpm test:unit:coverage
```

## Run Testnet integration (manual)

These tests hit real Hedera Testnet and incur costs. They are opt-in:

```bash
RUN_TESTNET_INTEGRATION=1 pnpm verify:testnet
RUN_TESTNET_INTEGRATION=1 GATEWAY_MODE=1 pnpm verify:testnet
RUN_TESTNET_INTEGRATION=1 USER_PAYS_MODE=1 pnpm verify:testnet
```

If running locally, ensure Postgres is available (see `docker-compose.yml`).

## Add a credential type via DB

Credential types are stored in the database.

1. Add a migration under `packages/db/migrations/`.
2. Use the existing schema patterns (e.g., `credential_types` table).
3. Run migrations with:
   ```bash
   pnpm --filter @cuncta/db build
   ```
   or by starting services (they auto-run migrations).

## Notes

- Do not commit secrets or `.env` files.
- Keep Hedera Testnet-only.
- Avoid changes to SSI runtime flows unless explicitly approved.
