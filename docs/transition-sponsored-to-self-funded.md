# Transition: Sponsored to Self-Funded Onboarding

This runbook describes how to move from sponsor-paid onboarding (gateway pays) to a user-pays model without
changing SSI core semantics or breaking existing clients.

## Phase 1: Sponsored default

- `ALLOW_SPONSORED_ONBOARDING=true`
- `ONBOARDING_STRATEGY_DEFAULT=sponsored`
- `ONBOARDING_STRATEGY_ALLOWED=sponsored,user_pays`
- Ensure budgets are sized for expected volume:
  - `SPONSOR_MAX_DID_CREATES_PER_DAY`
  - `SPONSOR_MAX_ISSUES_PER_DAY`
- Testnet pilots may use a single account as both sponsor and payer for convenience
  (never on mainnet, never in production).

Client UX:

- Default to sponsored.
- Offer a visible “Self-funded” option for advanced users.

## Phase 2: Hybrid

- Keep `ALLOW_SPONSORED_ONBOARDING=true`
- Move default to user-pays:
  - `ONBOARDING_STRATEGY_DEFAULT=user_pays`
- Keep both in allowed list:
  - `ONBOARDING_STRATEGY_ALLOWED=sponsored,user_pays`

Client UX:

- Default to self-funded.
- Keep sponsored toggle for support/partners.
- Use gateway-only user-pays endpoints for DID create submit (no direct DID service URLs).

## Phase 3: Self-funded default + disable sponsorship

- Set `ALLOW_SPONSORED_ONBOARDING=false`
- Keep allowed list to user-pays only:
  - `ONBOARDING_STRATEGY_ALLOWED=user_pays`
- Keep default aligned:
  - `ONBOARDING_STRATEGY_DEFAULT=user_pays`

Expected gateway response:

- `403` with `error="sponsored_onboarding_disabled"` and message `Self-funded required`.

Client UX guidance:

- Detect the 403 and switch to self-funded automatically if payer credentials are available.
- Otherwise, prompt for user-pays credentials (in browser/CLI only; never send to backend).
- For user-pays, build and sign the Hedera transaction locally and submit via
  `POST /v1/onboard/did/create/user-pays/submit` (gateway).

## Kill switch + rollback

- Set `SPONSOR_KILL_SWITCH=true` to stop all sponsor-paid transactions immediately.
- To temporarily re-enable sponsorship, set `ALLOW_SPONSORED_ONBOARDING=true` and adjust budgets.

## Safety notes

- Never send payer private keys to backend services.
- Keep DID creation, SD-JWT issuance/verification, policy, Aura, DSR, and anchoring semantics unchanged.
- Test each phase on Testnet before production rollout.
