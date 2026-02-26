# Policy & Catalog Admin Runbook

This runbook ensures policy/catalog updates are signed, audited, and anchored.

## Preconditions

- `POLICY_SIGNING_JWK` and `ANCHOR_AUTH_SECRET` present
- Change reviewed and approved
- Access to DB limited and audited

## Policy Change Steps

1. Apply policy change in DB (policy row update).
2. Ensure `POLICY_SIGNING_BOOTSTRAP=true` for the policy-service.
3. Restart policy-service or trigger policy evaluation to force integrity signing.
4. Confirm policy audit entry appears in `audit_logs` with new chain head.
5. Verify `anchor_outbox` contains `POLICY_CHANGE` for the new hash.
6. Confirm `anchor_receipts` show the new payload hash.
7. Set `POLICY_SIGNING_BOOTSTRAP=false` after changes.

## Catalog Change Steps

1. Apply catalog change in DB (credential_types row update).
2. Ensure `POLICY_SIGNING_BOOTSTRAP=true` for issuer-service.
3. Trigger catalog fetch or issuance to force integrity signing.
4. Confirm audit entry and `CATALOG_CHANGE` anchor event.
5. Set `POLICY_SIGNING_BOOTSTRAP=false` after changes.

## Verification

- `/healthz` reports `auditLog.headHash` and recent `anchoredAt`
- `anchor_outbox_backlog` returns to normal
- No `policy_integrity_failed` or `catalog_integrity_failed` errors

## Notes

- Policy/catalog integrity is enforced; invalid signatures deny evaluation.
- Audit log chain is anchored; monitor anchors for freshness.
