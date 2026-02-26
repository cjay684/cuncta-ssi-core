# Security Posture (Summary)

This monorepo implements a Hedera-only SSI platform with:

- Wallet-first key custody (holder private keys remain on device)
- Replay-resistant issuance and presentation flows
- Hash-only server-side persistence (no raw DIDs/credentials/presentations/claims stored)
- Hedera Testnet default, mainnet gated by explicit config

## Threat Model (High Level)

Assume a hostile environment:

- Active network attackers (MITM, replay, downgrade attempts)
- Malicious or compromised clients (reusing tokens, forging responses)
- SSRF attempts via any URL inputs
- Insider risk via logs and operational data access

## Key Controls

- One-time challenges: `verification_challenges` consumed on first use
- OID4VCI pre-authorized codes: hash-only + TTL + one-time semantics on `/token`
- OID4VCI proof-of-possession: `/credential` requires `proof.jwt` bound to `c_nonce` and issuer audience
- OID4VP request object signing: `request_jwt` is canonical truth; wallet verifies via JWKS
- OID4VP request replay: hash-only `oid4vp_request_hashes` consumed on first response
- Origin audience binding: verifier enforces `origin:` audiences in strict posture
- DID ↔ `cnf.jwk` binding: verifier enforces holder key authorization via DID Document in strict posture

## Issuer/Verifier Trust Model

Core does not assume that “any DID can be an issuer we accept”.

- Trust enforcement is policy-driven and data-driven:
  policies can require issuers to be present in the signed trust registry (`issuer.mode: trust_registry`).
- The registry bundle is signed (EdDSA) and verified at runtime; verification fails closed if required and unavailable.
- Trust marks are accreditation/allowlist signals (not “social credit”).

See `docs/trust-registry.md`.

## ZK Tracks (Optional)

ZK/DI tracks are feature-gated for production safety:

- `ALLOW_EXPERIMENTAL_ZK` defaults to `true` in dev/test and `false` in production unless explicitly enabled.
- When `ALLOW_EXPERIMENTAL_ZK=false`, verifier rejects DI+BBS presentations and any policy requirements that include `zk_predicates`.

Phase 6 (`di+bbs`):

- BBS derived proofs are unlinkable by design; verifier validates the derived proof and enforces KB-JWT binding.
- No JSON-LD remote context fetching is performed (no SSRF-by-context).

Phase 7 (`age_credential_v1` + Groth16 predicate proofs):

- Age credentials are issued as SD-JWT VCs containing only a DOB commitment (`dob_commitment`) + scheme version (no DOB ever sent to servers).
- Proof is a Groth16 SNARK over BN254 (`groth16_bn254`) proving `age >= min_age` without revealing DOB.
- Proof is bound to `nonce` + `audience/origin` + `request_hash` via public inputs and explicit verifier checks (prevents replay/context swapping).
- Verifier dispatch is data-driven via `@cuncta/zk-registry`: statement definitions reference circuit artifacts by path + SHA-256.

Commitment scheme (domain separated):

- Commitment lives in the VC as a public value, but the witness `(birthdate_days, rand)` stays on-device.
- `commitment_scheme_version=poseidon_v1_bn254_ds1`
- Commitment formula:
  - `domain_tag = sha256("cuncta:age:v1") mod p` (BN254 scalar field)
  - `dob_commitment = Poseidon(domain_tag, birthdate_days, rand)`

Trusted setup provenance + mainnet posture:

- Groth16 requires circuit-specific setup.
- This repo vendors dev-grade artifacts for the MVP circuit, generated locally via `packages/zk-age-snark` using `snarkjs` `beacon` (non-interactive, reproducible for CI/dev).
- Registry statements include `setup_provenance`. On mainnet, verifier requires `setup_provenance=ceremony_attested` and fails closed otherwise.

Artifact governance:

- Runtime: `@cuncta/zk-registry` hash-locks artifact files (sha256) and verifier fails closed if mismatched.
- CI: `scripts/security/zk-registry-hash-scan.mjs` fails if any referenced artifact file changes without a matching registry hash update.

Circuit upgrade procedure (non-breaking):

- Add a new versioned statement definition (new `statement_id` or bumped `version`) referencing new artifacts by hash.
- Keep previous statement enabled for an overlap period (verifier can accept both if policy permits).
- Deprecate old statements by setting `deprecated=true` in registry once no longer needed.

ZK-specific threats & mitigations:

- `downgrade`: policies declare `formats` and `zk_predicates`; verifier enforces `format_mismatch`/`zk_proof_missing`
- `parameter poisoning`: verifier pins artifacts by SHA-256 (registry loader validates files match definitions; CI gate enforces repo consistency)
- `malleability/replay`: context binding + one-time request hash consumption
- `proving key compromise`: treat proving keys as public; protect verifier key artifacts against tampering (hash-locked registry)
- `side-channels`: on-device proving may leak timing/power; treat wallet devices as potentially observable and keep circuits/witness handling minimal

## Logging Discipline

- Logs must remain hash-only.
- Never log raw `Authorization` headers, bearer tokens, raw DIDs, SD-JWT strings, KB-JWT/proof JWTs.
- CI includes a log PII scan gate to prevent regressions.

## Operational Notes

- Set `TRUST_PROXY=true` in production behind a proxy.
- Require `PSEUDONYMIZER_PEPPER` in production.
- Mainnet requires explicit `ALLOW_MAINNET=true` (guardrail).

# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it privately.

**Contact:** security@cuncta.com  
**Expected response time:** 5 business days

Please include:

- A detailed description of the issue
- Steps to reproduce
- Any proof-of-concept code (if available)
- Impact assessment

We will acknowledge receipt and work with you on a coordinated disclosure timeline.
