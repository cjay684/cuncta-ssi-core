# Gateway Compromise Runbook

## Detection signals

- Spike in `rate_limit_rejects_total` and `requests_total` on app-gateway metrics.
- Unexpected growth in `sponsor_budget_consumed_today` and drop in `sponsor_budget_remaining`.
- Log bursts of `request.complete` with unfamiliar IP hashes.

## Immediate containment (8-12 steps)

1. Block public ingress to app-gateway at the edge (WAF / firewall).
2. Set `SPONSOR_KILL_SWITCH=true` to stop sponsor spend.
3. Set `ALLOW_SPONSORED_ONBOARDING=false` to force client self-funded mode.
4. Rotate `SERVICE_JWT_SECRET` using the dual-secret flow in `docs/runbooks/chaos-and-misconfiguration.md`.
5. Redeploy app-gateway with the new `SERVICE_JWT_SECRET`.
6. Redeploy did/issuer/verifier services with `SERVICE_JWT_SECRET_NEXT` set.
7. Inspect app-gateway logs for `request.complete` and `verify.proxy.*` anomalies.
8. Verify app-gateway `/healthz` shows kill switch active and budgets stable.
9. Re-enable ingress only after verifying normal metrics and logs.
10. Remove `SERVICE_JWT_SECRET_NEXT` and redeploy internal services to finalize rotation.

## Key rotation steps

- `SERVICE_JWT_SECRET` (gateway minting) and `SERVICE_JWT_SECRET_NEXT` (service verification).

## Service restart order

1. app-gateway
2. did-service
3. issuer-service
4. verifier-service

## Post-incident verification checklist

- `sponsor_kill_switch_active == 1` until explicitly re-enabled.
- `sponsor_budget_remaining` stable after ingress restored.
- No unexpected spikes in `rate_limit_rejects_total`.
- Downstream services reject old service tokens.
