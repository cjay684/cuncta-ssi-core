# Compliance Posture (CUNCTA SSI Core)

## Scope

- CUNCTA SSI Core is a trust and identity layer for issuance and verification.
- It is not a user database, not a wallet custodian, and not a consumer account system.

## Data minimisation

- We store hashes, indices, and timestamps only.
- We do NOT store raw SD-JWTs, raw presentations, raw claims, or PII.
- Pseudonymous identifiers are keyed (HMAC) to reduce linkability; erasure can be strengthened by key destruction.
  Legacy hashes may be supported temporarily during migration.

## Data subject rights (DSR)

- Access/export uses proof-of-control of the holder DID (KB-JWT bound to nonce/audience).
- Restriction/objection stops further capability and obligation processing for the subject.
- Erasure unlinks off-chain state and adds a tombstone; on-chain HCS anchors remain immutable.
- Tombstoned subjects are blocked from new issuance and verification (error: `privacy_erased`).
- DSR bearer tokens rotate on each operation (export/restrict/erase); old tokens are invalidated immediately.

## Retention & storage limitation

- Default retention windows are configurable in `.env.example` (verification challenges 7d, rate limits 7d,
  obligations 30d, audit logs 90d).
- Cleanup removes expired/consumed challenges and telemetry tables only.
- Status lists and anchor receipts/outbox are intentionally retained for integrity.

## Rate limiting & abuse prevention

- Rate limits are designed to protect payer budgets, prevent abuse, and reduce denial-of-service risk.
- Limits should be tuned per deployment based on expected traffic and user onboarding volume.
- Monitor `rate_limit_rejects_total` and `requests_total` for sustained spikes and investigate anomalies.

## Automated decision-making

- Decisioning is policy-driven and capability-based; there is no global score.
- Human review hooks live in application policy and governance processes.

## Roles & responsibilities

- SSI Core can act as controller or processor depending on deployment and data flow.
- Legal basis, notices, and sector obligations are owned by the deploying application and its operators.

## References

- See `docs/threat-model.md` for storage limitation details and immutable anchors.
- See `docs/runbooks/chaos-and-misconfiguration.md` for operational failure and recovery scenarios.
- GDPR/UK GDPR alignment is a design goal; this document is descriptive, not legal advice.
