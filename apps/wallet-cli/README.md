# Wallet CLI

Client-managed signing for `did:hedera` using the DID service.

## Commands

```bash
pnpm --filter wallet-cli did:create
pnpm --filter wallet-cli did:create:auto --mode user_pays
pnpm --filter wallet-cli did:create:user-pays
pnpm --filter wallet-cli did:create:user-pays-gateway
pnpm --filter wallet-cli did:resolve
pnpm --filter wallet-cli smoke
pnpm --filter wallet-cli smoke:full
pnpm --filter wallet-cli vc:issue:age
pnpm --filter wallet-cli present:age
pnpm --filter wallet-cli smoke:strict
```

`smoke:strict` performs a full nonce/audience bound presentation with KB-JWT.

## Env

Set `HEDERA_NETWORK` in your `.env` if you want something other than the default `testnet`.
Self-funded onboarding requires payer credentials locally.
On Testnet in non-production, if `HEDERA_PAYER_*` is missing, the CLI will fall back to
`HEDERA_OPERATOR_*` and warn once: "Using operator credentials as payer (testnet/dev only)".
This fallback is never allowed on mainnet or in production.

```bash
export DID_SERVICE_BASE_URL=http://localhost:3001
export APP_GATEWAY_BASE_URL=http://localhost:3010
export HEDERA_NETWORK=testnet
export ONBOARDING_STRATEGY_DEFAULT=user_pays
export ONBOARDING_STRATEGY_ALLOWED=user_pays
export HEDERA_PAYER_ACCOUNT_ID=0.0.x
export HEDERA_PAYER_PRIVATE_KEY=302e...
export USER_PAYS_MAX_FEE_TINYBARS=50000000
```

`did:resolve` uses `APP_GATEWAY_BASE_URL` if set, otherwise falls back to `DID_SERVICE_BASE_URL`.

## Curl equivalents

Create request:

```bash
curl -s "$DID_SERVICE_BASE_URL/v1/dids/create/request" \
  -H "content-type: application/json" \
  -d '{
    "network": "testnet",
    "publicKeyMultibase": "z...",
    "options": {
      "topicManagement": "shared",
      "includeServiceEndpoints": true
    }
  }'
```

Submit:

```bash
curl -s "$DID_SERVICE_BASE_URL/v1/dids/create/submit" \
  -H "content-type: application/json" \
  -d '{
    "state": "uuid-from-request",
    "signatureB64u": "base64url-signature"
  }'
```

Resolve:

```bash
curl -s "$DID_SERVICE_BASE_URL/v1/dids/resolve/did:hedera:testnet:abc123"
```
