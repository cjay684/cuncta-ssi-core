# Backup & Restore Runbook

This runbook prevents serving traffic during restores and validates integrity before re‑opening.

## Preconditions

- Backup file verified and stored securely
- `ANCHOR_AUTH_SECRET`, `POLICY_SIGNING_JWK`, `PSEUDONYMIZER_PEPPER` available
- Service envs ready for production (no dev flags)
- `PRIVACY_ERASE_EPOCH_EXPECTED` is available from last known good deployment metadata

## Restore Steps

1. Set `BACKUP_RESTORE_MODE=true` for all services.
2. Deploy or restart services so maintenance mode is active.
3. Confirm endpoints return `503` for onboarding/issuance/verification/DSR.
4. Restore database from backup.
5. Run migrations: `pnpm --filter @cuncta/db migrate` (or service startup migration).
6. Read current epoch from DB:
   - `select value from system_metadata where key='privacy_erase_epoch';`
7. Set `PRIVACY_ERASE_EPOCH_EXPECTED` to the expected minimum epoch for this environment.
8. Start issuer-service first and confirm startup integrity checks pass.
9. Start other services and verify `/healthz` returns `ok: true`.

## Validation Checklist

- `issuer-service` startup integrity checks passed (no failures in logs)
- `pseudonymizer` fingerprint matches previous environment
- At least one ACTIVE issuer key exists
- Tombstones present if erasures ever occurred
- `privacy_erase_epoch` present and not regressed
- `auditLog.headHash` present in `/healthz`
- `anchor_outbox_backlog` stabilizes

## Post‑Restore Verification

1. Confirm `auditLog.anchoredAt` updates after anchor worker runs.
2. Run a test issuance/verify flow in a non‑production environment.
3. Compare anchor receipts count growth against expected volume.

## Return to Service

1. Set `BACKUP_RESTORE_MODE=false`.
2. Restart services.
3. Confirm onboarding/issuance/verification/DSR endpoints return normal responses.

## Notes

- Do not serve traffic while `BACKUP_RESTORE_MODE=true`.
- If integrity checks fail, stop and investigate DB state before enabling traffic.
- Issuer startup now fails with `restore_epoch_regression` when restored data is older than expected erase epoch.
- Never lower `PRIVACY_ERASE_EPOCH_EXPECTED` to bypass startup checks.
