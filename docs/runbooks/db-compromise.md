# Database Compromise Runbook

## Detection signals

- Unusual DB access patterns outside expected service accounts.
- Unexpected spikes in `outbox_rows_total` or `anchor_outbox_backlog`.
- Unexplained changes in policy/catalog integrity checks (`policy_integrity_failed` / `catalog_integrity_failed`).

## Immediate containment (8-12 steps)

1. Restrict DB network access to service subnets only.
2. Rotate `DATABASE_URL` credentials and redeploy services.
3. Restart services in this order: policy-service, issuer-service, verifier-service, did-service, app-gateway.
4. Enable `SPONSOR_KILL_SWITCH=true` and `ALLOW_SPONSORED_ONBOARDING=false` to reduce blast radius.
5. Rotate `SERVICE_JWT_SECRET` using the dual-secret flow.
6. If `ISSUER_KEYS_ALLOW_DB_PRIVATE=true`, rotate issuer keys via `/v1/internal/keys/rotate`.
7. If issuer key rotation is not configured, redeploy issuer-service with new key material (via `ISSUER_JWK` or KMS).
8. Review audit logs (`audit_logs` hashes) and service logs for anomalous activity.
9. Revoke compromised credentials via `/v1/revoke` (service auth required).
10. Validate policy/catalog integrity checks pass after rotation.

## Key rotation steps

- `DATABASE_URL` credentials.
- `SERVICE_JWT_SECRET` + `SERVICE_JWT_SECRET_NEXT`.
- Issuer signing key (via rotation endpoint or configured key material).

## Service restart order

1. policy-service
2. issuer-service
3. verifier-service
4. did-service
5. app-gateway

## Post-incident verification checklist

- `policy_integrity_failed` and `catalog_integrity_failed` errors absent.
- `anchor_outbox_backlog` stabilizes.
- Service auth rejects old tokens.
