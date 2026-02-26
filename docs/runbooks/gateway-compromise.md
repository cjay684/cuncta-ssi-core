# Gateway Compromise Runbook

## Detection signals

- Spike in `rate_limit_rejects_total` and `requests_total` on app-gateway metrics.
- Log bursts of `request.complete` with unfamiliar IP hashes.

## Immediate containment (8-12 steps)

1. Block public ingress to app-gateway at the edge (WAF / firewall).
2. Temporarily disable onboarding by setting `ALLOW_SELF_FUNDED_ONBOARDING=false`.
3. Rotate `SERVICE_JWT_SECRET` using the dual-secret flow in `docs/runbooks/chaos-and-misconfiguration.md`.
4. Redeploy app-gateway with the new `SERVICE_JWT_SECRET`.
5. Redeploy did/issuer/verifier services with `SERVICE_JWT_SECRET_NEXT` set.
6. Inspect app-gateway logs for `request.complete` and `verify.proxy.*` anomalies.
7. Verify app-gateway `/healthz` and confirm normal error rates and expected posture flags.
8. Re-enable ingress only after verifying normal metrics and logs.
9. Remove `SERVICE_JWT_SECRET_NEXT` and redeploy internal services to finalize rotation.

## Key rotation steps

- `SERVICE_JWT_SECRET` (gateway minting) and `SERVICE_JWT_SECRET_NEXT` (service verification).

## Service restart order

1. app-gateway
2. did-service
3. issuer-service
4. verifier-service

## Post-incident verification checklist

- No unexpected spikes in `rate_limit_rejects_total`.
- Downstream services reject old service tokens.
