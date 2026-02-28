# Chaos & Misconfiguration Runbook

## Purpose & Scope

This runbook covers intentional chaos testing and common misconfiguration scenarios.
It applies to issuer-service, verifier-service, and shared infrastructure.
This runbook assumes Hedera Testnet only.

## Pseudonymizer Pepper Mismatch

The pseudonymizer pepper is the secret input used to HMAC-hash DIDs into stable,
non-reversible pseudonyms. All services that read/write pseudonymized data must
share the same pepper to keep hashes consistent.

If peppers differ, services compute different hashes for the same subject, which
fragments data and makes historical state appear missing.

### Dev/Test mismatch

**Conditions**

- `NODE_ENV=development`
- issuer pepper != verifier pepper

**Expected behavior**

- Services start.
- Single log event: `pseudonymizer.mismatch`
- Metric `legacy_rows_present` unaffected.
- Observable symptoms: fragmented capability/DSR/rate-limit data (missing historical state).

**Operator action**

- Fix environment variables so both services share the same pepper.
- Restart services.

### Production mismatch

**Conditions**

- `NODE_ENV=production`
- pepper mismatch

**Expected behavior**

- Startup fails.
- Error: `pseudonymizer_mismatch`.

**Operator action**

- Do not override.
- Correct pepper distribution.
- Redeploy.

## Legacy Hash Visibility

Legacy SHA-256 hashes are the pre-HMAC pseudonymization format. Legacy reads may be
disabled to complete crypto-shredding and prevent linking across old hashes.

**Scenario**

- `PSEUDONYMIZER_ALLOW_LEGACY=false`
- Legacy rows still exist

**Expected behavior**

- Warning log: `pseudonymizer.legacy_rows_present`
- Metric: `legacy_rows_present = 1`
- No startup failure
- Historical data ignored

**Operator action**

- Decide whether the loss of historical linkage is intentional (crypto-shredding).
- Re-enable legacy reads temporarily if needed.
- Plan migration or accept loss of historical linkage.

## Status List Availability (Verifier)

Verifier depends on the issuer status list endpoint for revocation checks. The
security posture is fail-closed.

### Transient outage

**Condition**

- Issuer down for less than cache TTL

**Expected behavior**

- Verification succeeds using cached list.
- Metric: `status_list_cache_hit_total` increments.

### Extended outage

**Condition**

- Issuer down longer than cache TTL

**Expected behavior**

- Verification DENY.
- Reason: `status_list_unavailable`.

**Operator action**

- Restore issuer availability.
- Monitor deny spikes and cache miss metrics.

## Service Auth Misconfiguration

`SERVICE_JWT_SECRET` is required for service-to-service auth in production. The
insecure dev auth toggle is only allowed for local development (loopback bind or `LOCAL_DEV=true`).

### Missing SERVICE_JWT_SECRET in production

**Expected behavior**

- Startup fails.
- Error: `service_auth_not_configured`.

**Operator action**

- Correct environment.
- Redeploy.
- Never override in production.

## Dev Endpoints Access

Dev-only endpoints (`/v1/dev/*`) are available only when `NODE_ENV=development` and `DEV_MODE=true`.
Access requires either a loopback bind or a service JWT with scope `issuer:dev_issue`.

**Expected behavior**

- When `DEV_MODE=false` or not in development, endpoints return `404`.
- When not local and missing/invalid service auth, endpoints deny (404/401/403).

### Short or malformed SERVICE_JWT_SECRET

**Condition**

- `SERVICE_JWT_SECRET` (or per-service secret) < 32 characters
- or `SERVICE_JWT_SECRET_FORMAT_STRICT=true` and value is not base64url/hex

**Expected behavior**

- Startup fails.
- Error: `service_jwt_secret_format_invalid:<ENV_NAME>` or schema validation failure.

**Operator action**

- Replace secrets with >=32 char values.
- Prefer base64url (>=43 chars) or hex (>=64 chars).

## Public Binding Guard (Production)

Services refuse to bind to non-private interfaces in production.

**Condition**

- `NODE_ENV=production`
- `SERVICE_BIND_ADDRESS` is public or unspecified (e.g. `0.0.0.0`, `::`) on any service

**Expected behavior**

- Startup fails.
- Error: `refusing_to_bind_publicly_in_production`.

**Operator action**

- Set `SERVICE_BIND_ADDRESS=127.0.0.1` or a private network address (RFC1918 / ULA).
- Redeploy.

## Public Service Flag Misuse (Production)

Only the gateway may be public in production.

**Condition**

- `NODE_ENV=production`
- `PUBLIC_SERVICE=true` on any non-gateway service

**Expected behavior**

- Startup fails.
- Error: `public_service_not_allowed`.

**Operator action**

- Set `PUBLIC_SERVICE=false`.
- Redeploy.

## Trust Proxy Disabled (Production)

Rate limiting and IP hashing depend on correct client IPs.

**Condition**

- `NODE_ENV=production`
- `TRUST_PROXY=false` on any service

**Expected behavior**

- Startup fails.
- Error: `trust_proxy_required_in_production`.

**Operator action**

- Configure reverse proxy to set `X-Forwarded-For`.
- Set `TRUST_PROXY=true`.
- Redeploy.

## ISSUER_JWKS in Production (Verifier)

Verifier must fetch JWKS dynamically in production.

**Condition**

- `NODE_ENV=production`
- `ISSUER_JWKS` set on verifier-service

**Expected behavior**

- Startup fails.
- Error: `issuer_jwks_disabled_in_production`.

**Operator action**

- Remove `ISSUER_JWKS`.
- Ensure issuer-service `/jwks.json` is reachable from verifier.
- Redeploy.

## Service JWT Rotation (Dual Secret)

Use `SERVICE_JWT_SECRET_NEXT` to rotate service auth without downtime.

**Rotation flow**

1. Set `SERVICE_JWT_SECRET_NEXT` on did/issuer/verifier services.
2. Update app-gateway `SERVICE_JWT_SECRET` to the new value.
3. Redeploy app-gateway first (it mints with current secret only).
4. Redeploy internal services (they accept current + next).
5. Remove old secret by unsetting `SERVICE_JWT_SECRET_NEXT`.
6. Redeploy internal services to enforce the new secret only.

### ALLOW_INSECURE_DEV_AUTH=true outside local dev

**Expected behavior**

- Startup fails.
- Error: `insecure_dev_auth_not_allowed`.

**Operator action**

- Correct environment.
- Redeploy.
- Never override in production.

## Anchor Outbox Dead-Letter

Anchor outbox rows that exceed `ANCHOR_MAX_ATTEMPTS` are marked `DEAD` and no longer retried.

**Detection**

- `/healthz` reports `outbox.dead`.
- Metrics: `anchor_outbox_dead` (gauge), `anchor_outbox_dead_total` (counter).

**Operator action**

1. Inspect `anchor_outbox` rows where `status='DEAD'`.
2. Fix root cause (Hedera outage, auth, malformed payloads).
3. Manually requeue by setting `status='PENDING'`, `next_retry_at=now`, and incrementing `attempts` only if safe.
4. Monitor `anchor_outbox_dead_total` and `anchor_outbox_backlog`.

## DSR Erasure & Proof

Erasure means off-chain unlinking: the system deletes or nulls subject-linked
rows and writes a tombstone record. On-chain anchors are immutable and are not
erased.

**Primary proof**

- Tombstone row in `privacy_tombstones` with `erased_at` timestamp.

**Supporting evidence**

- Service log event `privacy.erase` with subject hash.
- Audit logs (hash-only) are retained for system events; use them where applicable.

**Explicit boundary**

- Erasure events are not anchored on-chain.

**Operator response to auditor**

- Show tombstone timestamp.
- Show absence of subject-linked rows in telemetry tables.
- Explain immutable anchoring boundary.

## Legacy Onboarding Routes (Disabled)

CUNCTA supports self-funded onboarding only. Legacy onboarding endpoints are permanently disabled.

**Expected behavior**

- Gateway routes `/v1/onboard/did/create/request`, `/v1/onboard/did/create/submit`, and `/v1/onboard/issue`
  return `410 Gone`.
- Error payload: `error="sponsored_onboarding_not_supported"` with message `Legacy onboarding is not supported. Use self-funded flows only.`

**Operator action**

- Clients must use self-funded flows (`/v1/onboard/did/create/user-pays/*`).

## Operator-as-Payer on Mainnet (Misconfiguration)

Testnet-only convenience allows operator creds to act as payer for demos and integration.
This must never be used on mainnet or in production.

**Condition**

- `HEDERA_NETWORK` is not `testnet`, or `NODE_ENV=production`, and `HEDERA_PAYER_*` is missing.

**Expected behavior**

- User-pays flows fail fast with a clear error requiring `HEDERA_PAYER_*`.
- No fallback to operator credentials.

**Operator action**

- Provide explicit payer credentials.
- Ensure mainnet deployments separate operator and payer roles.

## Checklist Summary

| Scenario               | Loud or Silent | Detection       | Operator Action     |
| ---------------------- | -------------- | --------------- | ------------------- |
| Pepper mismatch (prod) | Loud           | Startup failure | Fix env, redeploy   |
| Pepper mismatch (dev)  | Loud warning   | Logs            | Fix env             |
| Legacy rows disabled   | Loud warning   | Metric/log      | Accept or re-enable |
| Status list outage     | Loud deny      | Metrics         | Restore issuer      |
| Service auth missing   | Loud           | Startup failure | Fix env             |
