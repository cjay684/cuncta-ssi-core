# Mainnet Config-Only Migration Runbook

Goal: migrate the same codebase from Hedera testnet to Hedera mainnet using configuration + new keys only (no code edits).

## Preconditions

- All services build/typecheck/test clean: `pnpm -r build`, `pnpm -r typecheck`, `pnpm -r test`
- Staging smoke has passed on testnet using real network calls: `pnpm run smoke:staging`
- You have a production deployment process for providing secrets (do not commit JWKs)

## Generate Required Ed25519 JWKs

Run these locally (prints private JWK JSON; store in your secrets manager).

```bash
node -e "import { generateKeyPair, exportJWK } from 'jose'; const { privateKey } = await generateKeyPair('EdDSA',{crv:'Ed25519',extractable:true}); const jwk = await exportJWK(privateKey); jwk.kid='oid4vci-token-1'; jwk.alg='EdDSA'; console.log(JSON.stringify(jwk));"
node -e "import { generateKeyPair, exportJWK } from 'jose'; const { privateKey } = await generateKeyPair('EdDSA',{crv:'Ed25519',extractable:true}); const jwk = await exportJWK(privateKey); jwk.kid='verifier-oid4vp-1'; jwk.alg='EdDSA'; console.log(JSON.stringify(jwk));"
node -e "import { generateKeyPair, exportJWK } from 'jose'; const { privateKey } = await generateKeyPair('EdDSA',{crv:'Ed25519',extractable:true}); const jwk = await exportJWK(privateKey); jwk.kid='policy-1'; jwk.alg='EdDSA'; console.log(JSON.stringify(jwk));"
```

Map them to:

- `OID4VCI_TOKEN_SIGNING_JWK` (issuer-service)
- `VERIFIER_SIGNING_JWK` (verifier-service)
- `POLICY_SIGNING_JWK` (policy-service)

## Mainnet Switch (Env Only)

Set:

- `HEDERA_NETWORK=mainnet`
- `ALLOW_MAINNET=true`
- `NODE_ENV=production`

Disable all dev/test bootstrap flags (must be false/unset on mainnet production):

- `BREAK_GLASS_DISABLE_STRICT=false`
- `OID4VCI_TOKEN_SIGNING_BOOTSTRAP=false`
- `VERIFIER_SIGNING_BOOTSTRAP=false`
- `ISSUER_KEYS_BOOTSTRAP=false`
- `POLICY_SIGNING_BOOTSTRAP=false`

Enforce self-funded onboarding only:

- `ALLOW_SELF_FUNDED_ONBOARDING=true`
- `ONBOARDING_STRATEGY_DEFAULT=user_pays`
- `ONBOARDING_STRATEGY_ALLOWED=user_pays`

Reconciliation must be enabled:

- `ANCHOR_RECONCILIATION_ENABLED=true`
- `ANCHOR_RECONCILER_POLL_MS=...` (ops choice; 5m–1h typical)

Mirror node base URL:

- leave `MIRROR_NODE_BASE_URL` empty to use default `https://mainnet.mirrornode.hedera.com/api/v1`
- or set `MIRROR_NODE_BASE_URL=https://<your-mirror>/api/v1` (must include `/api/v1`)

## Readiness Gate (Fail Fast)

Run (with your real prod env injected):

```bash
pnpm run check:mainnet-ready
```

This fails if any mainnet+production-required key/config is missing or if any bootstrap/sponsored flag is enabled.

## Mainnet Smoke (Same Procedure)

The staging smoke harness is network-agnostic; it uses `HEDERA_NETWORK` + `ALLOW_MAINNET`.

```bash
HEDERA_NETWORK=mainnet ALLOW_MAINNET=true pnpm run smoke:staging
```

You must supply mainnet payer keys (`HEDERA_PAYER_ACCOUNT_ID` / `HEDERA_PAYER_PRIVATE_KEY`) and mainnet service URLs.

## Rollback Plan (Config Only)

If you need to roll back from mainnet:

- revert deployment env to `HEDERA_NETWORK=testnet` and `ALLOW_MAINNET=false`
- restore the previous keys/secrets (do not reuse compromised keys)
- keep `BREAK_GLASS_DISABLE_STRICT` off; treat break-glass as an incident-only tool and forbidden on mainnet production

