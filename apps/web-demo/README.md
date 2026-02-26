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

## 5-minute demo script

### Setup

1. `pnpm install`
2. `pnpm dev` (start core services)
3. `pnpm -C apps/web-demo dev`
4. Open `http://localhost:5173`
5. Ensure `DEV_MODE=true` and `SERVICE_JWT_SECRET` is unset for demo runs.

### Step-by-step demo

1. Create identity (DID).
2. Try “Check permission to list item” → expect **Not permitted yet**.
3. Request a demo proof **or** import a proof (Developer tools) → try again and expect **Action permitted**.
4. Simulate a successful listing → claim a derived reputation proof.
5. View the reputation explanation.
6. Export your data (hash-only).
7. Restrict processing → show reputation stops updating.
8. Erase/unlink → show data cleared (anchors remain immutable).

### Notes

- DEV_MODE-only behavior: the “Simulate successful listing” action is dev-only.
- Service auth disabled: no service JWTs are minted in this demo.
- Anchors are immutable: erase/unlink removes off-chain data, not on-chain HCS anchors.
- Client-side only: keys and proofs stay in the browser.
- Self-funded mode: payer keys are used in-browser only and never sent to backend.
- Testnet convenience: if payer keys are missing, you can explicitly opt-in to use the operator
  account for demo. This is blocked outside testnet.
- Environment presets: use “Load demo endpoints” or “Current origin” in the banner.
- Demo checklist: collapsible checklist tracks progress for live demos.

## Manual checklist

- Create DID
- Perform gated action (DENY → ALLOW after proof)
- Simulate reputation signal + claim derived proof
- Export DSR data
- Restrict → reputation stops updating
- Erase → data unlinked

## Security notes

- Private keys stay in memory only.
- No keys or JWTs are logged to console.
- All proofs are signed client-side and bound to nonce + audience.
