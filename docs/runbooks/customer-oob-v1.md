# Customer Out-of-the-Box Runbook v1 (Hedera Testnet, Real Flows)

This runbook exercises the production-intent rails (OID4VCI 1.0 + OID4VP 1.0-ish direct_post.jwt) with:

- Real cryptography (device-side keys in `wallet-cli`)
- Real Hedera Testnet (HCS + mirror)
- Self-funded only onboarding (no sponsored onboarding)
- No server-side raw DID / credential / presentation persistence (hash-only TTL state only)

See also:

- `docs/runbooks/key-recovery.md` (non-custodial recovery via DID rotation)
- `docs/compliance-profiles.md` (UK/EU profile overlays, data-driven)
- `docs/trust-registry.md` (signed issuer/verifier trust metadata)
- `docs/runbooks/fee-budgets.md` (self-funded fee caps + failure modes)

## Prereqs

- Node.js 20+
- pnpm 10+
- Postgres 16+
- Hedera Testnet payer account (self-funded mode)

## 1) Configure env

Copy `.env.example` to `.env` and fill the required values.

Minimum for local testnet runs:

- `HEDERA_NETWORK=testnet`
- `ALLOW_MAINNET=false`
- `DATABASE_URL=postgres://...`
- `PSEUDONYMIZER_PEPPER=...` (required for production posture)
- `SERVICE_JWT_SECRET=...` and per-service overrides if used
- `APP_GATEWAY_PUBLIC_BASE_URL=http://localhost:3010`
- `DID_SERVICE_BASE_URL=http://localhost:3001`
- `ISSUER_SERVICE_BASE_URL=http://localhost:3002`
- `VERIFIER_SERVICE_BASE_URL=http://localhost:3003`
- `POLICY_SERVICE_BASE_URL=http://localhost:3004`

## 2) Start services

```sh
pnpm install
pnpm migrate
pnpm dev
```

Health checks:

```sh
curl -s http://localhost:3001/healthz
curl -s http://localhost:3002/healthz
curl -s http://localhost:3003/healthz
curl -s http://localhost:3004/healthz
curl -s http://localhost:3010/healthz
```

## 3) Create a DID (self-funded)

This generates device keys locally and submits to Hedera Testnet using your payer credentials.

```sh
set WALLET_DIR=.tmp-wallet\oob
set DID_SERVICE_BASE_URL=http://localhost:3001
set APP_GATEWAY_BASE_URL=http://localhost:3010
set HEDERA_NETWORK=testnet

set HEDERA_PAYER_ACCOUNT_ID=0.0.xxxx
set HEDERA_PAYER_PRIVATE_KEY=302...

pnpm -C apps/wallet-cli wallet did:create:auto --mode user_pays
pnpm -C apps/wallet-cli wallet did:resolve
```

## 4) Acquire a credential via OID4VCI offer flow

The gateway mints an OID4VCI credential offer (pre-authorized code). The wallet redeems it via:
offer → `/token` → `/credential` with `proof.jwt`.

```sh
set ISSUER_SERVICE_BASE_URL=http://localhost:3002
set APP_GATEWAY_BASE_URL=http://localhost:3010

pnpm -C apps/wallet-cli wallet vc:acquire --config-id cuncta.marketplace.seller_good_standing
```

### 4b) Acquire an Aura capability VC via OID4VCI (portable entitlement)

Aura capability VCs are domain-scoped and require a holder-signed, one-time offer challenge (prevents the offer endpoint from becoming an eligibility oracle).

Marketplace (domain-scoped):

```sh
pnpm -C apps/wallet-cli wallet vc:acquire --config-id aura:cuncta.marketplace.trusted_seller_tier --claims-json "{\"domain\":\"marketplace\"}"
```

Social (domain-scoped):

```sh
pnpm -C apps/wallet-cli wallet vc:acquire --config-id aura:cuncta.social.trusted_creator --claims-json "{\"domain\":\"social\"}"
```

Space (space-scoped):

```sh
set SPACE_ID=<uuid>
pnpm -C apps/wallet-cli wallet vc:acquire --config-id aura:cuncta.social.space.moderator --claims-json "{\"space_id\":\"%SPACE_ID%\"}"
```

If you are not currently eligible, issuance fails with a 404-style `aura_not_ready`.

Optional (Phase 6): acquire `di+bbs` (BBS selective disclosure)

This requires provisioning a BBS keypair for the issuer and sharing the public key with the verifier and wallet.

Generate a keypair:

```sh
pnpm -C packages/di-bbs keys:gen
```

Set (in `.env`) for `issuer-service` and `verifier-service`:

- `ISSUER_BBS_SECRET_KEY_B64U=...`
- `ISSUER_BBS_PUBLIC_KEY_B64U=...`

Acquire:

```sh
set ISSUER_BBS_PUBLIC_KEY_B64U=...
pnpm -C apps/wallet-cli wallet vc:acquire --config-id cuncta.marketplace.seller_good_standing --format di+bbs
```

Optional (Phase 7): acquire `age_credential_v1` (commitment-only, ZK-ready)

The wallet generates a hiding+binding commitment to DOB locally and sends only the commitment to the issuer (issuer never sees DOB).

```sh
set WALLET_BIRTHDATE_DAYS=9000
pnpm -C apps/wallet-cli wallet vc:acquire --config-id age_credential_v1
```

## 5) Request a presentation (standard OID4VP surface)

```sh
curl -s "http://localhost:3010/oid4vp/request?action=marketplace.list_item&verifier_origin=https%3A%2F%2Fmerchant.example" > .tmp-oid4vp-request.json
```

Optional (Phase 7): ZK age-gated action

```sh
curl -s "http://localhost:3010/oid4vp/request?action=dating_enter&verifier_origin=https%3A%2F%2Fdating.example" > .tmp-oid4vp-request-zk.json
```

## 6) Present via direct_post.jwt (vp_token + presentation_submission)

```sh
set APP_GATEWAY_BASE_URL=http://localhost:3010
pnpm -C apps/wallet-cli wallet vp:respond --request "$(type .tmp-oid4vp-request.json)"
```

Optional (Phase 7):

```sh
pnpm -C apps/wallet-cli wallet vp:respond --request "$(type .tmp-oid4vp-request-zk.json)"
```

Expected: output JSON contains `"decision":"ALLOW"`.

## 7) Revoke and verify DENY

Revoke is a service-authenticated admin action (no holder secrets involved).

```sh
# Example shape; see issuer-service routes for required inputs.
curl -s -X POST http://localhost:3002/v1/credentials/revoke ^
  -H "content-type: application/json" ^
  -H "authorization: Bearer <service-jwt>" ^
  -d "{\"credentialFingerprint\":\"...\"}"
```

Then re-run the same request/present and expect `"decision":"DENY"` (strict mode revocation).

## 8) DSR erase (Right to Erasure)

See `apps/issuer-service/src/routes/privacy.ts` for the full flow. At a high level:

1. `POST /v1/privacy/request` (get nonce)
2. Wallet signs KB-JWT bound to nonce + audience
3. `POST /v1/privacy/confirm`
4. `POST /v1/privacy/erase`

Wallet helper:

```sh
pnpm -C apps/wallet-cli wallet privacy:flow
```

