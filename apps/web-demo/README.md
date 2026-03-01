# CUNCTA Web Demo

This is a minimal React frontend that demonstrates how a real application integrates with CUNCTA SSI Core. It is a demo/reference implementation, not a production wallet.

## Run locally

1. Start the core services (did, issuer, verifier, policy).
2. Install dependencies (from repo root):

```bash
pnpm install
```

3. Run the web demo:

```bash
pnpm -C apps/web-demo dev
```

Open `http://localhost:5173`.

## Environment variables

Set these in your shell or a `.env.local` file:

- `VITE_DID_SERVICE_BASE_URL` (default: `http://localhost:3001`)
- `VITE_APP_GATEWAY_BASE_URL` (default: `http://localhost:3010`)
- `VITE_ISSUER_SERVICE_BASE_URL` (default: `http://localhost:3002`)
- `VITE_VERIFIER_SERVICE_BASE_URL` (default: `http://localhost:3003`)
- `VITE_POLICY_SERVICE_BASE_URL` (default: `http://localhost:3004`)
- `VITE_KBJWT_TTL_SECONDS` (optional, clamped 30–600, default 120)
- `VITE_ONBOARDING_STRATEGY_DEFAULT` (`user_pays`; CUNCTA supports self-funded only)
- `VITE_ONBOARDING_STRATEGY_ALLOWED` (comma list)
- `VITE_HEDERA_NETWORK` (default `testnet`)
- `VITE_HEDERA_OPERATOR_ID` + `VITE_HEDERA_OPERATOR_PRIVATE_KEY` (testnet demo fallback only)

If `SERVICE_JWT_SECRET` is enabled on core services, the demo will receive `401` responses because
there is no backend to mint service tokens. For local demo runs, leave `SERVICE_JWT_SECRET` unset.

## Security notes

- Private keys stay in memory only.
- No keys or JWTs are logged to console.
- All proofs are signed client-side and bound to nonce + audience.
