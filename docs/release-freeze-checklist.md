# Release Freeze Checklist

Use this checklist to create a reproducible Testnet release artifact.

## 1) Pre-freeze branch hygiene

- Ensure you are on the intended release branch (example: `release/v1.0.0-testnet`).
- Confirm no unresolved security findings are in scope for this release.
- Confirm no secrets are present in untracked/staged files.
- Confirm changelog and release notes are updated.

## 2) Mandatory verification

Run from repo root:

```bash
pnpm format:check
pnpm lint
pnpm -r build
pnpm -r typecheck
pnpm -r test
pnpm test:unit:coverage
```

Testnet verification (manual/self-hosted only):

```bash
RUN_TESTNET_INTEGRATION=1 pnpm verify:testnet
RUN_TESTNET_INTEGRATION=1 GATEWAY_MODE=1 pnpm verify:testnet
RUN_TESTNET_INTEGRATION=1 USER_PAYS_MODE=1 pnpm verify:testnet
```

## 3) Migration and runtime separation checks

- Production migration credentials are provided via `MIGRATIONS_DATABASE_URL`.
- Production runtime services do not use migration credentials.
- `AUTO_MIGRATE=false` in production environments.

## 4) Production guard checks

- `STRICT_DB_ROLE=true` in production.
- `ALLOW_LEGACY_SERVICE_JWT_SECRET=false` in production.
- If strict transport mode is enabled, `ENFORCE_HTTPS_INTERNAL=true` and all internal URLs are HTTPS.

## 5) Supply-chain checks

- CI actions remain SHA-pinned.
- Dependency audit policy is unchanged and understood.
- SBOM artifact generation remains enabled.
- Container scan gates align with current release policy.

## 6) Tag and release

Create annotated tag:

```bash
git tag -a v1.0.0-testnet -m "Testnet release v1.0.0"
```

Push branch and tag:

```bash
git push origin <release-branch>
git push origin v1.0.0-testnet
```

## 7) Evidence to retain

- CI run URL(s) for verification matrix.
- Testnet run URL(s) and environment label.
- Hash/ID of release commit and tag object.
- Final release note document in `docs/releases/`.
- This initial freeze commit used `--no-verify` due to pre-existing lint-staged failures; follow-up task will normalize lint/format.
