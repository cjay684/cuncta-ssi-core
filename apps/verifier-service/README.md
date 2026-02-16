# Verifier Service

Presentation verification gateway for CUNCTA modules.

## Strict vs compat

- Strict mode enforces `typ=dc+sd-jwt`.
- If `SDJWT_COMPAT_LEGACY_TYP=true`, legacy `vc+sd-jwt` is accepted but flagged in diagnostics.

## Strict flow

- Verifier generates a random nonce and audience per request.
- Holder binds the presentation with a KB-JWT signed by the holder key.
- Verifier checks SD-JWT signature, disclosures, status list, and KB-JWT binding.

## Not OID4VP

Internal endpoints are **not** OID4VP protocol shapes. Use:

```bash
POST /v1/presentations/request
POST /v1/presentations/verify
```

## Integrity boundary (MVP)

Verification trusts issuer anchoring and status list contents. Mirror node anchoring checks are deferred.

## Env

```bash
export ISSUER_SERVICE_BASE_URL=http://localhost:3002
export ISSUER_JWKS='{"keys":[{"kty":"OKP","crv":"Ed25519","x":"...","kid":"issuer","alg":"EdDSA"}]}'
export SDJWT_COMPAT_LEGACY_TYP=false
```

## Example

```bash
curl -s http://localhost:3003/v1/presentations/request \
  -H "content-type: application/json" \
  -d '{
    "policyId": "policy-1",
    "audience": "cuncta.verifier",
    "nonce": "1234"
  }'
```
