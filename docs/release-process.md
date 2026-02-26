# Release Process

This repo supports multiple Hedera networks. Mainnet runs require explicit opt-in
(`ALLOW_MAINNET=true`) and should follow the mainnet readiness checklist before release.

Related docs:

- `docs/release-freeze-checklist.md`
- `docs/security-posture.md`
- `docs/releases/v1.0.0-security-hardening.md`

## Tag and freeze

1. Create a release branch (e.g., `release/v1.0.0-testnet`).
2. Freeze changes except for release fixes.
3. Update `CHANGELOG.md`.

## Verification matrix

Run the following before tagging:

```bash
pnpm format:check
pnpm lint
pnpm -r build
pnpm -r typecheck
pnpm -r test
pnpm test:unit:coverage
```

Testnet (manual, self-hosted):

```bash
RUN_TESTNET_INTEGRATION=1 pnpm verify:testnet
RUN_TESTNET_INTEGRATION=1 GATEWAY_MODE=1 pnpm verify:testnet
RUN_TESTNET_INTEGRATION=1 USER_PAYS_MODE=1 pnpm verify:testnet
```

## Tag

```bash
git tag -a v1.0.0-testnet -m "Testnet release v1.0.0"
```
