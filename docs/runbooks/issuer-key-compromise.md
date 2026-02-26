# Issuer Signing Key Compromise Runbook

## Detection signals

- Unexpected issuance volume in issuer logs (`issuer.issue.request`).
- Verifier failures for newly issued credentials.
- Alerting from credential consumers about invalid signatures.

## Immediate containment (8-12 steps)

1. Block public access to issuer-service if exposed.
2. Rotate `SERVICE_JWT_SECRET` using the dual-secret flow to prevent internal misuse.
3. If `ISSUER_KEYS_ALLOW_DB_PRIVATE=true`, call `/v1/admin/keys/rotate` to mint a new ACTIVE key.
4. Revoke the compromised `kid` via `/v1/admin/keys/revoke`.
5. Redeploy issuer-service to ensure key ring is refreshed.
6. Ensure verifier-service fetches updated JWKS from issuer `/jwks.json`.
7. Re-issue credentials that must remain valid.
8. Revoke any credentials suspected to be signed with the compromised key via `/v1/revoke`.
9. Confirm issuer `/jwks.json` includes only ACTIVE + RETIRED keys (no revoked key).
10. Re-enable public access only after validation.

## Key rotation steps

- Issuer signing key via `/v1/admin/keys/rotate` and `/v1/admin/keys/revoke`.

## Service restart order

1. issuer-service
2. verifier-service
3. app-gateway (if applicable)

## Post-incident verification checklist

- New credentials verify successfully against `/v1/verify`.
- Old compromised `kid` is revoked in key ring.
- JWKS cache on verifier refreshes (restart or wait for cache TTL).
