# Repo Readiness Report (Evidence-Backed)

This report is generated from executable checks + code evidence.

## Baseline health

Commands (repo root):

- `pnpm -r build`
- `pnpm -r typecheck`
- `pnpm -r test`

Status: PASS (all green in this workspace run).

## Real Hedera Testnet E2E (Required)

Canonical testnet E2E command (gateway posture):

```powershell
$env:HEDERA_NETWORK="testnet"
$env:ALLOW_MAINNET="false"
$env:GATEWAY_MODE="1"
pnpm verify:testnet
```

Expected success sentinel:

- `Integration tests complete.`

## Hard requirements checklist

### Ledger: Hedera only

- DID method SDK: `@hiero-did-sdk/*` (registrar/resolver)
- Hedera SDK: `@hashgraph/sdk`
- Mirror node reads: `MIRROR_NODE_BASE_URL` defaults include `/api/v1` and are derived from `HEDERA_NETWORK`

### Self-funded onboarding only (no sponsorship)

- Legacy sponsored endpoints are present only to return `410 Gone` with `sponsored_onboarding_not_supported`:
  - `apps/app-gateway/src/routes/onboard.ts`
- Startup rejects `ALLOW_SPONSORED_ONBOARDING=true`:
  - `apps/app-gateway/src/config.ts`

### Canonical consumer APIs: OID4VCI + OID4VP via gateway

- OID4VP consumer request/response routes:
  - `apps/app-gateway/src/routes/oid4vp.ts`
- OID4VCI issuer routes:
  - `apps/issuer-service/src/routes/issuer.ts`

### OID4VP request signing + wallet verification (strict)

- Gateway attaches `request_jwt` (service-auth to verifier signing endpoint):
  - `apps/app-gateway/src/routes/oid4vp.ts`
- Gateway exposes `/.well-known/jwks.json` (proxy):
  - `apps/app-gateway/src/routes/verify.ts`
- Wallet rejects unsigned requests in strict posture:
  - `apps/wallet-cli/src/commands/vpRespond.ts`

### Admin APIs under `/v1/admin/*` only

- Admin endpoints and scopes documented:
  - `docs/admin-api.md`
- Scope enforcement supports `admin:*` wildcard:
  - `packages/shared/src/serviceAuth.ts`

### Strict posture defaults

- Origin-scoped audience default-on in verifier:
  - `apps/verifier-service/src/config.ts` (`ENFORCE_ORIGIN_AUDIENCE` defaults true unless break-glass)
- Break-glass forbidden on mainnet+production:
  - `apps/verifier-service/src/config.ts`
  - `apps/app-gateway/src/config.ts`

### Anchor reconciliation is operationally real

- Scheduled reconciler + persistence (`anchor_reconciliations`):
  - `apps/issuer-service/src/hedera/anchorReconciler.ts`
- Admin operator endpoint:
  - `apps/issuer-service/src/routes/anchors.ts`

### Mainnet config-only gate exists + fails fast

- Script: `scripts/mainnet-readiness-check.ts`
- Script wiring: `package.json` (`check:mainnet-ready`)

## DID subsystem audit

See `docs/did-subsystem.md`.

