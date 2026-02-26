# Issuer Service

SD-JWT VC issuer with Bitstring Status List revocation and Hedera HCS anchoring.

## Strict vs compat

- Strict mode issues SD-JWT VC with `typ=dc+sd-jwt` (default).
- If `SDJWT_COMPAT_LEGACY_TYP=true`, the `/credential` endpoint accepts `format: "vc+sd-jwt"` but marks the request as non-conformant via `x-non-conformant: true`.

## Anchoring

- Credential issuance hashes and Status List VC hashes are anchored on HCS.
- The anchor message payload contains `{ kind, sha256, metadata }`.

## Integrity boundary (MVP)

Anchors are published at the issuer boundary. Mirror node verification is deferred.

## Identities

- **Issuer DID** is server-managed and bootstrapped via the did-service client-signing flow.
- The issuer DID + key material is persisted in `apps/issuer-service/data/issuer-did.json`.
- **Holder DID** is provided by the wallet as `subjectDid` and must be different from the issuer DID.
- Leave `ISSUER_DID` unset. If it is set to the holder DID, it will be ignored and a new issuer DID will be bootstrapped.

## Endpoints

```bash
GET  /healthz
GET  /.well-known/openid-credential-issuer
POST /token
POST /credential
GET  /status-lists/:listId
POST /v1/credentials/revoke
POST /v1/dev/issue
GET  /jwks.json
GET  /v1/issuer
```

## Env

```bash
export ISSUER_BASE_URL=http://localhost:3002
export ISSUER_JWK='{"kty":"OKP","crv":"Ed25519","d":"...","x":"...","alg":"EdDSA","kid":"issuer"}'
export DID_SERVICE_BASE_URL=http://localhost:3001
export HEDERA_NETWORK=testnet
export HEDERA_OPERATOR_ID=0.0.x
export HEDERA_OPERATOR_PRIVATE_KEY=302e...
export HEDERA_ANCHOR_TOPIC_ID=0.0.x
```

## Dev issue

```bash
curl -s http://localhost:3002/v1/dev/issue \
  -H "content-type: application/json" \
  -d '{
    "subjectDid": "did:hedera:testnet:abc",
    "claims": { "name": "Ada" },
    "vct": "cuncta.id",
    "statusListId": "default"
  }'
```

## Status list

```bash
curl -s http://localhost:3002/status-lists/default
```
