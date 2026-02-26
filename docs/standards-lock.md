# CUNCTA SSI Standards Lock (Jan 2026)

## SD-JWT VC (fast lane credential format)

- SD-JWT VC profile: draft-ietf-oauth-sd-jwt-vc-13 (Nov 2025)
- SD-JWT base: IETF RFC 9901
- Required typ: `dc+sd-jwt` (compat: `vc+sd-jwt` only when explicitly allowed)

## Status / Revocation

- W3C VC Bitstring Status List v1.0 (May 2025)
  Canonical TR: https://www.w3.org/TR/vc-bitstring-status-list/
  Errata: https://w3c.github.io/vc-bitstring-status-list/errata.html

## OpenID4VC (interoperability backbone)

- OpenID for Verifiable Credential Issuance (OID4VCI) 1.0 FINAL
  https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-final.html
- OpenID for Verifiable Presentations (OID4VP) 1.0 FINAL
  https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html

Note: internal endpoints remain internal even when aligned with OID4VCI/OID4VP semantics.

## VC Security

- W3C VC JOSE/COSE v1.0 (Recommendation)
  Canonical TR: https://www.w3.org/TR/vc-jose-cose/
  Errata: https://w3c.github.io/vc-jose-cose/errata.html

## DID guidance (not Rec; use as guidance)

- DID Resolution v0.3 (W3C TR; living document, not a Rec)

## Threat modeling guidance (not Rec)

- Threat Model for Decentralized Credentials (W3C Draft Note)
- Threat Modeling Guide for Decentralized Credentials (W3C Draft Note)

## Hedera-only anchoring

- DID method: did:hedera (Hedera/Hiero DID Method)
- did:hedera v2 (HIP-1219) treated as directional until SDKs finalize.

## Implemented now

- SD-JWT VC issuance/verification with `dc+sd-jwt`
- Bitstring Status List v1.0 for revocation
- Internal endpoints aligned to OID4VCI/OID4VP shapes

## Deferred

- Full OID4VCI/OID4VP public interop surface
- Private-lane credential formats (pluggable interface only)

## Interop risks

- External wallets expecting `vc+sd-jwt` typ may need compat mode enabled
- Partial OID4VCI/OID4VP means some clients require adapters
