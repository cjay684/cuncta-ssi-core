# DID Subsystem (did:hedera) — Audit Notes

This repo uses **Hedera-only** DIDs via the Hiero DID SDK (`@hiero-did-sdk/*`), with a self-funded (user-pays) onboarding flow surfaced through `app-gateway`.

## Components

- `apps/did-service`
  - Service-authenticated DID create endpoints
  - Public DID resolution endpoint
- `apps/app-gateway`
  - Public self-funded onboarding endpoints (`/v1/onboard/did/create/user-pays/*`)
  - Public DID resolution proxy (`/v1/dids/resolve/:did`)
- `apps/wallet-cli`
  - DID creation flows (local + via gateway user-pays)
- `apps/verifier-service`
  - DID resolution client with caching/timeouts
  - DID ↔ `cnf.jwk` binding enforcement

## 1) DID creation correctness (self-funded user-pays)

Public customer flow is implemented in `apps/app-gateway/src/routes/onboard.ts`:

- `POST /v1/onboard/did/create/user-pays/request`
  - returns a short-lived `handoffToken` + topic parameters
  - token is single-use (replay denied) and has strict size + fee caps
- `POST /v1/onboard/did/create/user-pays/submit`
  - wallet submits a signed Hedera `TopicMessageSubmitTransaction` (base64url)
  - gateway validates network/topic/max-fee and submits to Hedera

Wallet implementation (real Hedera transaction creation/signing + bounded retries):

- `apps/wallet-cli/src/commands/didCreate.ts`
  - `createDidUserPaysViaGateway()` hits gateway request/submit endpoints and signs the payload locally
  - `runWithHederaRetries()` adds bounded retry/backoff for transient Hedera failures
  - `waitForDidResolution()` polls `/v1/dids/resolve/:did` with a bounded timeout for visibility lag

did-service create endpoints remain **service-auth only** (not consumer-facing):

- `apps/did-service/src/routes/dids.ts`
  - `POST /v1/dids/create/request` requires `did:create_request`
  - `POST /v1/dids/create/submit` requires `did:create_submit`

## 2) DID resolution

Resolution endpoints:

- Gateway proxy: `apps/app-gateway/src/routes/dids.ts`
  - `GET /v1/dids/resolve/:did` (rate limited) proxies did-service
- did-service: `apps/did-service/src/routes/dids.ts`
  - `GET /v1/dids/resolve/:did` resolves via `@hiero-did-sdk/resolver`

Verifier-side resolution client (bounded timeout + cache, no loops):

- `apps/verifier-service/src/didResolver.ts`
  - timeout enforced via `AbortController` (`DID_RESOLVE_TIMEOUT_MS`)
  - LRU-ish bounded cache (`DID_RESOLVE_CACHE_TTL_SECONDS`, `DID_RESOLVE_CACHE_MAX_ENTRIES`)
  - inflight de-dupe to avoid stampedes

## 3) DID key binding (cnf.jwk ↔ DID Document keys)

When enabled (`ENFORCE_DID_KEY_BINDING=true`), verifier checks that the KB-JWT `cnf.jwk` public key is authorized by the subject DID document.

Implementation:

- `apps/verifier-service/src/didKeyBinding.ts`
  - supports Ed25519 keys as:
    - `publicKeyJwk` (`OKP`/`Ed25519`)
    - `publicKeyMultibase` (including multicodec-wrapped `0xed01 + 32B` raw key bytes)
  - considers keys referenced under `authentication` / `assertionMethod` relationships, falling back to all `verificationMethod`s if no relationships are present

## 4) Threat boundaries (did-service must not become a public signer)

- Consumer-facing onboarding is via `app-gateway` only.
- DID creation endpoints in did-service require service JWT scopes (no unauthenticated DID creation).

Evidence:

- Service auth enforcement: `apps/did-service/src/auth.ts`
- Route scopes: `apps/did-service/src/routes/dids.ts`

## 5) Mainnet config-only migration

All DID network selection is driven by config:

- `HEDERA_NETWORK=testnet|previewnet|mainnet`
- `ALLOW_MAINNET=true` is required to run on mainnet

Evidence:

- did-service mainnet guard: `apps/did-service/src/config.ts`
- wallet mainnet guard: `apps/wallet-cli/src/commands/didCreate.ts`

No code edits are required to switch testnet → mainnet; operators provide mainnet keys + config.
