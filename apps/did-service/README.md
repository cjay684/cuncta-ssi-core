# DID Service

Client-managed signing flow for `did:hedera`.

## Run

```bash
pnpm -C apps/did-service dev
```

## Create DID (request)

```bash
curl -s http://localhost:3001/v1/dids/create/request \
  -H "content-type: application/json" \
  -d '{
    "network": "testnet",
    "publicKeyMultibase": "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRtp7rYhQ",
    "options": {
      "topicManagement": "shared",
      "includeServiceEndpoints": false
    }
  }'
```

Response:

```json
{
  "state": "f4dd4f1a-37c9-4a70-a2d1-3b5d0d9a4a22",
  "signingRequest": {
    "publicKeyMultibase": "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRtp7rYhQ",
    "alg": "EdDSA",
    "payloadToSignB64u": "base64url_payload",
    "createdAt": "2026-01-29T19:00:00.000Z"
  }
}
```

## Create DID (submit)

```bash
curl -s http://localhost:3001/v1/dids/create/submit \
  -H "content-type: application/json" \
  -d '{
    "state": "f4dd4f1a-37c9-4a70-a2d1-3b5d0d9a4a22",
    "signatureB64u": "base64url_signature"
  }'
```

Response:

```json
{
  "did": "did:hedera:testnet:...",
  "didDocument": {},
  "hedera": {
    "topicId": "0.0.123456",
    "transactionId": "0.0.123456@1700000000.000000000"
  }
}
```

## Resolve DID

```bash
curl -s http://localhost:3001/v1/dids/resolve/did:hedera:testnet:abc123
```

Response:

```json
{
  "didDocument": {}
}
```
