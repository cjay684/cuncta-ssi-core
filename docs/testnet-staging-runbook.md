# Testnet Staging Deployment + Smoke Runbook (Real Network)

Goal: deploy the core services to publicly reachable HTTPS URLs on Hedera testnet, then prove the real customer path end-to-end using `wallet-cli` (no protocol mocks).

## Services + Public URLs

You need externally reachable base URLs for:

- `APP_GATEWAY_BASE_URL` (public entrypoint for customers)
- `ISSUER_SERVICE_BASE_URL` (public OID4VCI issuer + status lists)

Notes:

- The smoke harness uses the gateway as the DID resolver surface (`/v1/dids/resolve/:did`), so `did-service` may remain private as long as the gateway can reach it.
- The verifier JWKS is surfaced at `/.well-known/jwks.json` on the gateway (proxying verifier-service) when request signing is enabled.

## Required Staging Config (server-side)

These must be set in your staging deployment env (not on the laptop):

- `HEDERA_NETWORK=testnet`
- `ALLOW_MAINNET=false`
- Self-funded only:
  - `ALLOW_SELF_FUNDED_ONBOARDING=true`
  - `ONBOARDING_STRATEGY_DEFAULT=user_pays`
  - `ONBOARDING_STRATEGY_ALLOWED=user_pays`
- OID4VP signing enabled:
  - `VERIFIER_SIGN_OID4VP_REQUEST=true`
  - `VERIFIER_SIGNING_BOOTSTRAP=false`
  - `VERIFIER_SIGNING_JWK=<Ed25519 private JWK JSON>`
  - `APP_GATEWAY_PUBLIC_BASE_URL=https://<your-staging-gateway-host>`
  - `GATEWAY_SIGN_OID4VP_REQUEST=true`
- OID4VCI token signing enabled:
  - `ISSUER_ENABLE_OID4VCI=true`
  - `OID4VCI_TOKEN_SIGNING_BOOTSTRAP=false`
  - `OID4VCI_TOKEN_SIGNING_JWK=<Ed25519 private JWK JSON>`
- Anchor reconciliation enabled:
  - `ANCHOR_RECONCILIATION_ENABLED=true`
  - `ANCHOR_RECONCILER_POLL_MS=3600000` (or your ops interval)

## Required Operator Secrets (client-side for smoke)

The staging smoke is intended to be runnable in CI/CD with secrets, or by an operator workstation.

Set these env vars locally before running the harness:

- URLs:
  - `APP_GATEWAY_BASE_URL=https://<your-staging-gateway-host>`
  - `ISSUER_SERVICE_BASE_URL=https://<your-staging-issuer-host>`
- Network:
  - `HEDERA_NETWORK=testnet`
  - `ALLOW_MAINNET=false`
- Self-funded onboarding payer keys (real Hedera account on testnet):
  - `HEDERA_PAYER_ACCOUNT_ID=0.0.xxxxx`
  - `HEDERA_PAYER_PRIVATE_KEY=302e...` (or your SDK-supported string format)
- Issuer service-auth secret (for the operator-only steps: revoke + reconcile):
  - `SERVICE_JWT_SECRET_ISSUER=<>=32 chars secret>`
  - `SERVICE_JWT_AUDIENCE_ISSUER=cuncta.service.issuer` (only override if your deployment changed it)
- Optional (override what the smoke issues/verifies):
  - `SMOKE_ACTION=identity.verify`
  - `SMOKE_VCT=cuncta.age_over_18`

## Run The Smoke

From the repo root:

```bash
pnpm install
pnpm run smoke:staging
```

What the script proves (and fails fast if any step breaks):

1. DID create (self-funded via gateway `user_pays` flow; real Hedera topic submit)
2. OID4VCI acquire credential (real token endpoint + credential endpoint)
3. OID4VP request -> wallet response -> `ALLOW`
   - Wallet verifies `request_jwt` signature via `iss/.well-known/jwks.json` (strict default)
4. Revoke -> verify `DENY`
   - Operator revokes by `statusListId` + `statusListIndex` derived from the acquired credential
5. Anchor reconcile returns at least one `VERIFIED` result (with bounded retries for mirror lag)

## Troubleshooting

- If step (3) fails with `request_jwt_missing_strict_mode`: your staging gateway is not attaching signed requests to `/oid4vp/request` (request signing misconfigured).
- If step (4) never turns into `DENY`: status list caching/propagation is stalled or the policy doesn’t require revocation for the `SMOKE_ACTION`.
- If step (5) never yields `VERIFIED`: mirror lag, missing `ANCHOR_AUTH_SECRET`, or anchors are not being written (anchor worker/operator misconfig).
