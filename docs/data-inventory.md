# Data Inventory (GDPR / UK GDPR)

Principles:

- No raw holder DIDs, credentials, presentations, or claim values are persisted server-side.
- Any identifier-like values that must be persisted are stored as irreversible hashes or HMAC(pepper, DID).
- Short-lived protocol state uses hash-only TTL tables with one-time consumption.

## Persistent Stores

| Store | Location | Contains | PII Risk | Retention | DSR behavior |
|---|---|---|---|---|---|
| `verification_challenges` | Postgres | `challenge_hash`, action/policy hashes, expiry/consumed timestamps | Low (no raw nonce) | TTL via `RETENTION_VERIFICATION_CHALLENGES_DAYS` | Not directly linkable; expires/deletes |
| `oid4vci_preauth_codes` | Postgres | `code_hash`, `vct`, TTL, consumed timestamp | Low (no raw code) | TTL (minutes) + cleanup | Not linkable to DID; TTL delete |
| `oid4vci_c_nonces` | Postgres | `nonce_hash`, `token_jti_hash`, TTL, consumed timestamp | Low | TTL (minutes) + cleanup | Not linkable to DID; TTL delete |
| `oid4vp_request_hashes` | Postgres | `request_hash`, TTL, consumed timestamp | Low | TTL (minutes) | Not linkable to DID; TTL delete |
| `issuance_events` | Postgres | `subject_did_hash` (HMAC pepper), `vct`, credential fingerprints, status list pointers | Medium (pseudonymous) | Retention per issuer policy | `privacy/erase` unlinks `subject_did_hash` and writes tombstones |
| `status_lists` + versions | Postgres | revocation bitstrings (no subject identifiers) | Low | Operational | DSR not applicable (no subject identifiers) |
| `anchor_*` tables | Postgres | anchored payload hashes + receipts + reconciliation status | Low | Operational | DSR not applicable (hash-only) |
| `audit_logs` / `command_center_audit_events` | Postgres | operational telemetry, pseudonymous subject hashes | Medium (pseudonymous) | `RETENTION_AUDIT_LOGS_DAYS` | DSR erasure removes/unlinks subject hashes when present |

## Cryptographic Pseudonymization

- Holder DID linkage is pseudonymized using HMAC-SHA256 with `PSEUDONYMIZER_PEPPER`.
- Pepper must be stable per deployment to preserve DSR linkability. Pepper rotation requires an explicit migration plan.

## ZK Predicate Data Notes (Age >= 18)

- ZK statement registry files (`packages/zk-registry/statements/*.json`) are static code artifacts (not personal data); they define statement contracts, artifact hashes, and verifier/wallet/issuer expectations.
- `dob_commitment` is a pseudonymous personal data element (linkable if reused across contexts). It is issued inside the holder credential and disclosed to verifiers only when needed to bind a ZK proof.
- The platform does not persist DOB, DOB commitments, or ZK proof blobs server-side beyond in-flight request handling.
- `issuance_events.credential_fingerprint` for `age_credential_v1` is derived from the issued credential and may implicitly cover `dob_commitment` (treat as pseudonymous personal data).
- `zk_context.current_day` is non-personal and is carried only inside the signed OID4VP request object JWT (verifier enforces drift bounds); it is not stored server-side beyond the hash-only request replay table.

## Aura / Reputation (Capability System) Notes

- Aura is implemented as domain-scoped, product-specific capability derivation. It is not intended as a universal cross-domain score.
- Persistent identifiers in Aura (`subject_did_hash`, `counterparty_did_hash`) are pseudonymous personal data under GDPR/UK GDPR (linkable within a deployment if the pepper is known).
- Evidence is stored as hashes only (e.g., `aura_signals.event_hash`, optional `evidence_hash` on ingest), not raw content.
- Retention:
  - `aura_signals` is retained short by default (`RETENTION_AURA_SIGNALS_DAYS`, default 30) and cleaned by the cleanup worker.
  - `aura_state` is bounded (`RETENTION_AURA_STATE_DAYS`, default 180) and cleaned by the cleanup worker.
  - `aura_issuance_queue` terminal rows are bounded (`RETENTION_AURA_ISSUANCE_QUEUE_DAYS`, default 30) and cleaned by the cleanup worker.
- OID4VCI capability portability state:
  - `oid4vci_preauth_codes` stores `scope_hash` only (hash of wallet-supplied `scope_json`) for short-lived offer binding; it contains no raw DID, no raw scope, and expires quickly.
  - `oid4vci_offer_challenges` stores only `nonce_hash` + TTL for one-time offer challenges (prevents the offer endpoint becoming an eligibility oracle).
- Lawful basis (deployment-specific): typically Legitimate Interests for abuse prevention / product safety gating, or Contract for providing capability-gated product functionality. Document the basis per domain and capability.
- DSR: `privacy/erase` deletes aura-linked rows by subject hash and tombstones the subject to prevent re-linking.

## Legacy / Deprecated Stores

The following tables may exist in some deployments from earlier experimental ZK tracks. They are not used by the current Groth16 predicate flow.

| Store | Location | Contains | PII Risk | Retention | DSR behavior |
|---|---|---|---|---|---|
| `zk_age_groups` | Postgres | legacy Merkle roots for Semaphore-era age track | Low | Deprecated | DSR not applicable (no subject identifiers) |
| `zk_age_group_members` | Postgres | legacy `identity_commitment` + `subject_did_hash` | Medium (pseudonymous) | Deprecated | `privacy/erase` deletes rows by DID hash |

## Lawful Basis (Template)

Deployment owners must select and document one basis per processing purpose:

- Contract / pre-contract steps (service delivery)
- Legitimate interests (fraud/abuse controls, rate limiting)

Record your basis per store/purpose in deployment documentation.

