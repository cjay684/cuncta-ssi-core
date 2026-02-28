# CUNCTA SSI Threat Model (Jan 2026)

## Attacker models

- DB breach (read-only or full export)
- Insider abuse (misuse of credentials, keys, or admin paths)
- SSRF into internal services or metadata endpoints
- Replay of presentations or access tokens
- Correlation attempts across domains

## Mitigations implemented in code

- No PII in DB; store hashes and minimal metadata only
- SD-JWT selective disclosure for data minimization
- Strict `dc+sd-jwt` typ with explicit legacy compat flag
- Status list revocation checks for every verification (short-lived in-memory caching only)
- Verifier may use short-lived in-memory cache for status lists (TTL <= 60s) for availability; never persisted; still fail-closed when stale
- Nonce + audience binding in KB-JWT for replay resistance
- Outbox + idempotent Hedera HCS anchoring to prevent lost anchors
- Service-to-service JWT auth (aud/exp required) on sensitive endpoints
- Rate limits on public endpoints
- Audit logs with hashes only (no secrets or raw presentations)

## What we do NOT store

- Raw PII or full claims in DB
- Private keys or signing secrets (production mode)
- Raw SD-JWT tokens, raw signatures, or raw presentations
- Full JWT payloads
- Unhashed evidence payloads (only evidence hashes)

## Storage limitation (retention)

- Off-chain telemetry only (hashes + timestamps); on-chain anchors are immutable
- verification_challenges: 7 days (expired/consumed only)
- rate_limit_events: 7 days
- obligation_events: 30 days
- capability_signals: 90 days (capability_state retained as current summary)
- audit_logs: 90 days

## Data subject rights (DSR)

- DSR requests authenticate via proof-of-control of the holder DID (KB-JWT bound to nonce/audience)
- Export returns hash-only records and aggregate state (no raw tokens, claims, or presentations)
- Erasure unlinks off-chain state and adds a tombstone; on-chain HCS anchors remain immutable

## Residual risks / accepted risks

- Metadata correlation via access patterns (mitigated by minimization)
- Client misuse of compat mode for legacy typ
