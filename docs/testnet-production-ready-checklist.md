# CUNCTA — Testnet Production-Ready Checklist

This checklist assumes:

- No mocks
- Real Hedera Testnet
- Gateway-only public surface
- No server key custody
- No accounts / no user DB
- GDPR + unlinkability invariants preserved

## 1) Environment & deployment (hard gate)

- `HEDERA_NETWORK=testnet`
- `ALLOW_MAINNET` not set (or explicitly false)
- Separate Testnet-only:
  - issuer keys
  - registrar topic(s)
  - status list topic(s)
  - Postgres database
- `TRUST_PROXY=true` enforced for gateway
- Gateway is the only public service
- Internal services have no public ingress
- TLS enabled on gateway
- Secrets loaded from env/secret manager (not checked into repo)
- Fail-fast verified
- Services refuse to start if:
  - mainnet without `ALLOW_MAINNET=true`
  - pepper missing in production
  - service auth secrets missing
  - `CONTRACT_E2E_ENABLED=true` in production

## 2) Gateway posture (public attack surface)

- `/v1/capabilities` exposed, minimal, additive-only
- `/v1/requirements`:
  - rate limited
  - device-aware quotas enforced
  - `cache-control: no-store`
  - normalized error responses
- `/v1/verify`:
  - oracle-resistant response shape
  - no distinguishing errors in normal mode
- `/v1/dids/resolve/:did`:
  - rate limited
  - normalized errors
  - short cache TTL only
- Self-funded onboarding endpoints:
  - require `ALLOW_SELF_FUNDED_ONBOARDING=true`
  - stateless handoff token
  - tx type allowlist enforced
  - topic binding enforced
  - max fee enforced
  - size cap enforced
- Any CI/admin routes:
  - gated by env flag
  - require admin token
  - IP allowlist (CIDR)
  - refuse to start in production

## 3) Cryptography & binding (non-negotiable)

- DID creation:
  - client builds and signs real `TopicMessageSubmitTransaction`
  - gateway never signs
  - gateway never receives private keys
- Verification:
  - SD-JWT presentation built client-side
  - KB-JWT binding always required
  - `aud`, `nonce`, `exp` enforced
  - `sd_hash = SHA-256(UTF-8 presentation)` (base64url)
- KB-JWT:
  - signature verified against embedded `cnf.jwk`
  - `exp` in seconds (not ms)
- Replay protection:
  - challenge/nonce reuse fails
  - expired challenges fail

## 4) Wallet guarantees (mobile + CLI)

- No private keys ever leave device
- Dev-only software keys:
  - require explicit flag
  - refuse to start in production mode
- Vault:
  - encrypted at rest (AEAD)
  - wipe destroys keys + ciphertext
  - no plaintext SD-JWTs on disk
- Wallet enforces:
  - network match with gateway
  - gateway fee/size/TTL caps
  - expiry skew handling
- Raw `aud`:
  - always shown on confirmation UI
  - never logged
- Logs contain:
  - hashed identifiers only
  - no raw credentials
  - no raw presentations

## 5) Anti-phishing & disclosure

- Audience (`aud`) displayed before every presentation
- First-seen relying party warning
- Policy/catalog hash pinning:
  - first seen pins
  - changes trigger warning + explicit confirmation
- Selective disclosure:
  - user-chosen claims only
  - requirements-driven minimums
  - ambiguous mappings force manual selection
- No "disclose all by accident"

## 6) Contract E2E proof (must be run at least once)

Against real staging gateway + Hedera Testnet:

- `pnpm test:contract:e2e` passes
  - oracle resistance
  - replay resistance
  - revocation
  - gateway-only flows
- Wallet CLI:
  - `did:create:user-pays-gateway` succeeds
  - resolve via gateway succeeds
- Mobile wallet:
  - `verify:smoke` returns ALLOW/DENY
  - `verify:selective` works with real SD-JWT

This is the line between "code is correct" and "system is proven."

## 7) Documentation & operator clarity

- README explains:
  - testnet vs mainnet posture
  - gateway-only requirement
  - self-funded vs sponsored onboarding
- `.env.example` documents all safety-critical flags
- Known warnings documented (Node loader, fs.Stats)
- Runbooks exist for:
  - Testnet deployment
  - CI E2E runs
  - key/pepper rotation
  - wallet wipe / recovery expectations

## Definition of "Testnet production-ready"

A third party can deploy this stack on Hedera Testnet, run the wallet against it, issue and verify
credentials, and no private keys, PII, or linkable identifiers are exposed or stored server-side —
even under failure or abuse.
