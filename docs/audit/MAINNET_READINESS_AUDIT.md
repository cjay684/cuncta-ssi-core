# CUNCTA SSI Mainnet Readiness Audit

**Date:** 2025-02-20  
**Scope:** Ledger/DID, Keys/Crypto, Strict Mode, Identity/Privacy, Admin Surface, Data/DR, Consumer Experience, Mainnet Flip Simulation, Security Hardening

---

## 🧭 I. Ledger & DID Layer

### 1) DID Network Binding

**Is `did:hedera:{network}:...` fully derived from HEDERA_NETWORK?**

**Yes, with one exception.** Services (issuer, verifier, did-service, policy-service, app-gateway) read `HEDERA_NETWORK` from config and use it for mirror URLs and DID resolution. Mirror URL defaults per network:

```225:231:apps/issuer-service/src/config.ts
  const mirrorBaseUrl =
    parsed.MIRROR_NODE_BASE_URL ??
    (parsed.HEDERA_NETWORK === "mainnet"
      ? "https://mainnet.mirrornode.hedera.com/api/v1"
      : parsed.HEDERA_NETWORK === "previewnet"
        ? "https://previewnet.mirrornode.hedera.com/api/v1"
        : "https://testnet.mirrornode.hedera.com/api/v1");
```

**wallet-cli**

- `HEDERA_NETWORK` supports `testnet`, `previewnet`, and `mainnet`.
- `ALLOW_MAINNET=true` is required when `HEDERA_NETWORK=mainnet` (fail-fast).
- DID creation routes accept the network from config/inputs; no hardcoded testnet-only behavior is required for the mainnet flip.

### 2) Hedera SDK Assumptions

**SDK clients in dev vs prod**

- No separate dev/prod SDK initialization. All use `HEDERA_NETWORK` from config.
- `packages/hedera/src/mirror.ts` uses public mirror endpoints; no private/enterprise mirror wiring.

**Mirror endpoints**

- Defaults: `https://{network}.mirrornode.hedera.com/api/v1`.
- Public mirror only; no production-grade mirror configuration.
- Overridable via `MIRROR_NODE_BASE_URL`.

**Testnet assumptions**

- No explicit testnet-only fee or throttling logic.
- `ALLOW_MAINNET` is required for mainnet; verifier-service throws `mainnet_not_allowed` if `HEDERA_NETWORK=mainnet` and `ALLOW_MAINNET` is not set.

### 3) Anchor Throughput

**Anchors per event**

| Event | Anchors | Source |
|-------|---------|--------|
| Credential issuance | 1 (ISSUED) | `issuance.ts` |
| Revocation | 1 (REVOKED) | `issuance.ts` |
| Verification | 1 (OBLIGATION_EXECUTED) + optional ANCHOR_EVENT per policy | `obligations/execute.ts` |
| Social action (when `body.anchor` true) | 1 per action | `social.ts` (profile create, post, reply, etc.) |
| Catalog change | 1 (CATALOG_CHANGE) | `catalogIntegrity.ts` |
| Audit head | 1 (AUDIT_LOG_HEAD) per cleanup cycle | `cleanupWorker.ts` |

**Batching**

- No batching. One `anchor_outbox` insert per event.
- `OUTBOX_BATCH_SIZE` controls how many outbox rows the worker processes per tick, not how many events are batched into one anchor.

**Mainnet cost estimate**

- Not computed in code. Each credential ≈ 1 ISSUED anchor; each verify with obligations ≈ 1 OBLIGATION_EXECUTED; social actions with `anchor: true` add more. Hedera topic message fees apply per message.

---

## 🔐 II. Key & Crypto Management

### 4) Issuer Key Rotation

**Rotation without downtime**

- `keyRing.ts` supports rotation; RETIRED keys remain in JWKS.
- Admin `/v1/admin/keys/rotate` and `/v1/admin/keys/revoke` endpoints exist (service auth required).

**Previous keys in JWKS**

- Yes. Retired keys stay in JWKS for verification of old credentials.

**`kid` in issued credentials**

- SD-JWT uses `kid` from the active key; old signatures remain verifiable via JWKS.

### 5) Verifier Signing Key

**OID4VP request signing**

- OID4VP request signing is implemented (EdDSA).
- Verifier exposes `/.well-known/jwks.json`.
- Wallet verifies signed request JWTs via JWKS derived from `iss` (strict mode fails closed).

**Verifier key rotation**

- Via config + redeploy:
  - rotate by updating `VERIFIER_SIGNING_JWK` (and/or implementing a multi-key JWKS strategy)
  - JWKS is served at `/.well-known/jwks.json`

**JWKS endpoint**

- Issuer exposes `/.well-known/jwks.json`; verifier fetches issuer JWKS for credential verification.

### 6) OID4VCI Token Signing

**Algorithm**

- EdDSA (`at+jwt`) with `OID4VCI_TOKEN_SIGNING_JWK` in production.

**Key handling**

- Token signing key is configured via `OID4VCI_TOKEN_SIGNING_JWK` (required in production).
- `OID4VCI_TOKEN_SIGNING_BOOTSTRAP` is allowed in dev/test only.

**If secret leaks**

- Attacker can forge access tokens and obtain credentials. No rotation or key versioning for this secret.

**EdDSA/ES256**

- EdDSA supported; HS256 is not used for OID4VCI tokens.

---

## 🔄 III. Strict Mode & Policy

### 7) Strict Mode Default-On

**Current behavior (no special flags)**

| Check | Default | Config |
|-------|---------|--------|
| OID4VP requests signed | ✅ On | `VERIFIER_SIGN_OID4VP_REQUEST` defaults `true` |
| Origin audience enforced | ✅ On | `ENFORCE_ORIGIN_AUDIENCE` defaults `true` |
| Short expirations | ✅ Yes (challenge TTL, token TTL) | Configurable |
| Challenge single-use | ✅ Yes | Enforced in verify flow |

**Flags to enable**

- `ENFORCE_ORIGIN_AUDIENCE=true` for origin audience.
- `BREAK_GLASS_DISABLE_STRICT` exists (default off; forbidden on mainnet production).

### 8) Policy Integrity

**Version pinning**

- Policies are version-pinned via challenge (`policy_id`, `policy_version`).
- `POLICY_VERSION_FLOOR_ENFORCED` can enforce a minimum version.

**Tampering detection**

- Policy hash is signed with `POLICY_SIGNING_JWK`.
- Verifier verifies `policy_signature` and that `challengeRow.policy_hash === policyHash`.
- Compromised policy-service can still serve malicious policies; verifier validates signature and hash consistency.

**Policy hash in OID4VP request**

- Policy hash is bound to the challenge, not to the OID4VP request object itself. Challenge pins policy at creation time.

---

## 🧬 IV. Identity & Privacy

### 9) Pairwise Identifiers

**Canonical subject ID**

- `subject_did_hash` (SHA-256 of DID) is the primary identifier.
- No `subject_pairwise_hash` or pairwise scope in the codebase.

**Correlation across RPs**

- Same DID → same `subject_did_hash` across RPs.
- Logs and DB exports can correlate users across RPs via `subject_did_hash`.
- DSR export uses hashed identifiers; raw DIDs are not exposed.

### 10) Logs

**Raw DIDs / JWTs / tokens**

- Verifier: `log.ts` redacts keys matching `SENSITIVE_KEY` (includes `token`, `secret`, etc.). `tokenHash` is redacted.
- Issuer: uses `tokenHashPrefix()` (12-char hash prefix) for tokens.
- Privacy export test asserts no raw DIDs, JWTs, or SD-JWT in export output.

**Structured log hashing**

- `packages/shared/src/pseudonymizer.ts` provides `didToHash` (SHA-256 or HMAC-SHA256 with pepper).
- Not all logs use it; some logs may still include hash prefixes or non-redacted fields.

---

## 🏗 V. Admin / Operational Surface

### 11) Internal Endpoints

**Current state**

- `/v1/internal/*` endpoints are not used.
- Admin endpoints are under `/v1/admin/*` and require service auth scope (or `admin:*`).

**Auth**

- `requireServiceAuth` with scopes (e.g. `issuer:anchor_reconcile`).
- No “undocumented internal” endpoints; these are internal by path and auth.

### 12) Anchor Reconciliation in Prod

**Default**

- `ANCHOR_RECONCILIATION_ENABLED`: defaults to `true` and is required on mainnet production.

**Scheduling**

- Scheduled via `ANCHOR_RECONCILER_POLL_MS` (issuer-service background worker).
- Also callable via `POST /v1/admin/anchors/reconcile` (service auth required).

**Mirror verification failure**

- `anchorReconciler.ts` logs and increments metrics (`anchor_reconcile_total` with status).
- No explicit alerting; behavior is log + metric.

### 13) Rate Limiting

**Environment awareness**

- Limits are configurable via env (e.g. `RATE_LIMIT_IP_VERIFY_PER_MIN`, `RATE_LIMIT_IP_TOKEN_PER_MIN`).
- No automatic scaling by environment.

**Protected endpoints**

- Token: `RATE_LIMIT_IP_TOKEN_PER_MIN` (issuer).
- Credential: `RATE_LIMIT_IP_CREDENTIAL_PER_MIN` (issuer).
- Verify: `RATE_LIMIT_IP_VERIFY_PER_MIN` (gateway).
- DID, command, social, etc.: per-route limits in gateway.

**Gateway coverage**

- Gateway applies rate limits to public entrypoints it proxies.

---

## 🗄 VI. Data & Disaster Recovery

### 14) Postgres Loss

**Reconstruction from Hedera**

- Anchors store payload hashes and event metadata on Hedera.
- Revocation state: status list and revocation entries are in Postgres; not fully reconstructable from anchors alone.
- Social data: in Postgres; not in anchors.
- Anchors support audit/replay of issuance, verification, and obligation events, but not full system state.

### 15) DSR & Tombstones

**Tombstone scope**

- `privacy_tombstones` keyed by `did_hash` (global subject hash, not pairwise).
- Erase inserts tombstones for both primary and legacy DID hashes.

**Anchor history after erase**

- Tombstones prevent issuance and verification for erased subjects.
- Anchor history on Hedera remains; payload hashes do not directly expose DIDs, but event metadata could support correlation.

**Irreversibility**

- Erase is intended to be irreversible: tombstones, deletion of aura state, signals, and command audit.

---

## 🌍 VII. Consumer Experience

### 16) Public API Surface

**OID4VCI**

- `/.well-known/openid-credential-issuer` (metadata)
- `/token` (access token)
- `/credential` (credential issuance)
- `/jwks.json` (issuer keys)

**OID4VP**

- Request: challenge/requirements from gateway (`/v1/requirements`, `/v1/verify/requirements`).
- Response: POST to verifier (via gateway `/v1/verify`).

**Additional**

- `/v1/onboard/did/create/*` (DID creation)
- `/v1/capabilities`
- `/v1/verify` (presentation verification)
- `/v1/command/*` (command center)
- `/v1/social/*`, `/v1/media/*`, `/v1/realtime/*` (social features)

### 17) Wallet Compatibility

**In-repo wallet**

- `packages/wallet` and `apps/wallet-cli` are in-repo.

**Third-party wallet**

- OID4VCI: metadata, token, credential endpoints follow standard patterns.
- OID4VP: challenge/verify flow is custom; third-party wallets would need to implement the same flow.
- Non-standard: context predicates, space_id, policy pinning. Compliance depends on wallet implementation.

---

## 🧪 VIII. Mainnet Flip Simulation

**If you run today:**

```
HEDERA_NETWORK=mainnet
ALLOW_MAINNET=1
pnpm start
```

**What would break or need attention:**

| Area | Effect |
|------|--------|
| **Verifier** | Fails at startup if `ALLOW_MAINNET` not set; with `ALLOW_MAINNET=1` it runs. |
| **Issuer** | Same guard; with `ALLOW_MAINNET=1` it runs. |
| **wallet-cli** | `HEDERA_NETWORK=mainnet` fails env schema (`z.literal("testnet")`). |
| **createDidUserPays** | Hardcoded `network: "testnet"` in Registrar providers. |
| **Fees** | Mainnet fees apply; no fee handling changes. |
| **DID format** | `did:hedera:mainnet:...` used when network is mainnet. |
| **Mirror URL** | Defaults to mainnet mirror; overridable. |
| **Access tokens** | Unchanged. |
| **Rate limits** | Unchanged; consider tuning for mainnet. |
| **OID metadata** | `ISSUER_BASE_URL` must point to mainnet-facing URL. |
| **Reconciliation** | Disabled by default in production; enable explicitly if desired. |

---

## 🧠 IX. The Hard Question

**Would a security auditor find:**

| Category | Finding |
|----------|---------|
| **Dev-only shortcuts** | Operator-as-payer fallback (testnet/dev); `ANCHOR_RECONCILIATION_ENABLED=false` in prod; `ENFORCE_ORIGIN_AUDIENCE` off by default. |
| **Temporary fallbacks** | `OID4VCI_ACCESS_TOKEN_SECRET` fallback to `SERVICE_JWT_SECRET_ISSUER` / `SERVICE_JWT_SECRET`; shared secrets increase blast radius. |
| **Implicit trust** | Internal endpoints rely on service auth; policy-service compromise can affect policy content (integrity still enforced by verifier). |
| **TODO/FIXME in critical paths** | None in app code; only in `packages/wallet/node_modules/zod`. |

---

## Summary: Mainnet Readiness

**Ready with config changes**

- DID creation (gateway/did-service), resolution, key binding, OID flows.
- Mirror URL, anchor worker, verification flow.

**Requires code changes**

1. **wallet-cli**: Extend `HEDERA_NETWORK` to `mainnet` | `previewnet` | `testnet`; remove hardcoded `network: "testnet"` in `createDidUserPays`.
2. **Reconciliation**: Enable and schedule in production if desired.
3. **Strict mode**: Set `ENFORCE_ORIGIN_AUDIENCE=true` for production.

**Recommendations**

- Add `OID4VCI_ACCESS_TOKEN_SECRET` (dedicated, no fallback to `SERVICE_JWT_SECRET`).
- Consider EdDSA/ES256 for OID4VCI access tokens.
- Implement OID4VP request signing if required by security model.
- Use a production-grade mirror node for mainnet.
- Add scheduled reconciliation for production.
