# Hedera Operator Key Compromise Runbook

## Detection signals

- Unexpected DID create or anchor activity.
- Anchoring failures with `operator_not_configured` or abnormal anchor activity.
- Sudden sponsor budget depletion in gateway metrics.

## Immediate containment (8-12 steps)

1. Set `SPONSOR_KILL_SWITCH=true` to stop sponsor-funded actions.
2. Set `ALLOW_SPONSORED_ONBOARDING=false` to prevent sponsored onboarding.
3. Restrict outbound Hedera traffic at the network edge if required.
4. Rotate `HEDERA_OPERATOR_ID` / `HEDERA_OPERATOR_PRIVATE_KEY` (and DID/ANCHOR variants).
5. Update `HEDERA_DID_TOPIC_ID` or `HEDERA_ANCHOR_TOPIC_ID` if required for new operator ownership.
6. Redeploy did-service and issuer-service with new operator credentials.
7. Verify issuer anchor worker status in `/healthz` and metrics.
8. Re-enable sponsor operations only after validation.
9. Monitor `anchor_outbox_backlog` until it stabilizes.
10. Review issuer logs for `anchor.worker.failed` or unexpected anchors.

## Key rotation steps

- `HEDERA_OPERATOR_ID`, `HEDERA_OPERATOR_PRIVATE_KEY`.
- `HEDERA_OPERATOR_ID_DID`, `HEDERA_OPERATOR_PRIVATE_KEY_DID`.
- `HEDERA_OPERATOR_ID_ANCHOR`, `HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR`.

## Service restart order

1. did-service
2. issuer-service
3. app-gateway

## Post-incident verification checklist

- New DIDs can be created (sponsored or user-pays).
- Anchors resume without backlog growth.
- Sponsor budget remains stable after re-enabling.
