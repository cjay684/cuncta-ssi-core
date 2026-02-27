# Trust Registry (Issuer/Verifier Trust) — Signed, Data-Driven

Goal: avoid “anyone can be an issuer/verifier we accept” by introducing a signed, data-driven
trust layer that integrates with policy requirements and verification enforcement.

## What It Is

- A signed registry bundle (EdDSA) listing trusted issuers and verifiers plus optional trust marks.
- Verification is fail-closed: if a policy requires trust and the registry cannot be verified,
  verification must deny.

Data lives in:

- `packages/trust-registry/registries/default/bundle.json`

Bundle contents:

- `registry` (the data)
- `signature_jws` (EdDSA JWS over `{ registry_id, hash, iat }`)
- `verify_jwk` (public JWK used to verify the signature)

## How It Integrates

Policies can express issuer trust as data by using:

```json
{
  "issuer": {
    "mode": "trust_registry",
    "registry_id": "default",
    "trust_mark": "accredited"
  }
}
```

`verifier-service` enforces this at verification time (no mocks, no PII stores).

## Rotation / Updates

- The registry signature is designed to be rotated by publishing a new bundle.
- Operators should treat `verify_jwk` as pinned configuration.

## Security Notes

- Registry bundles must not contain PII (no emails, phone numbers, addresses).
- Trust marks are not “social credit”; they are simple accreditation/allowlist signals.
