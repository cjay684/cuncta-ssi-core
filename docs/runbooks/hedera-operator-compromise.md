# Hedera Operator Key Compromise Runbook

## Detection signals

- Unexpected DID create or anchor activity.
- Anchoring failures with `operator_not_configured` or abnormal anchor activity.
- Sudden fee payer / operator account depletion (unexpected HBAR spend).

## Immediate containment (8-12 steps)

1. Temporarily disable onboarding by setting `ALLOW_SELF_FUNDED_ONBOARDING=false` in app-gateway.
2. Restrict outbound Hedera traffic at the network edge if required.
3. Rotate `HEDERA_OPERATOR_ID` / `HEDERA_OPERATOR_PRIVATE_KEY` (and DID/ANCHOR variants).
4. Rotate `HEDERA_PAYER_ACCOUNT_ID` / `HEDERA_PAYER_PRIVATE_KEY` if used for user-pays onboarding.
5. Update `HEDERA_DID_TOPIC_ID` or `HEDERA_ANCHOR_TOPIC_ID` if required for new operator ownership.
6. Redeploy did-service and issuer-service with new operator credentials.
7. Verify issuer anchor worker status in `/healthz` and metrics.
8. Monitor `anchor_outbox_backlog` until it stabilizes.
9. Review issuer logs for `anchor.worker.failed` or unexpected anchors.

## Key rotation steps

- `HEDERA_OPERATOR_ID`, `HEDERA_OPERATOR_PRIVATE_KEY`.
- `HEDERA_OPERATOR_ID_DID`, `HEDERA_OPERATOR_PRIVATE_KEY_DID`.
- `HEDERA_OPERATOR_ID_ANCHOR`, `HEDERA_OPERATOR_PRIVATE_KEY_ANCHOR`.
- `HEDERA_PAYER_ACCOUNT_ID`, `HEDERA_PAYER_PRIVATE_KEY` (if configured).

## Service restart order

1. did-service
2. issuer-service
3. app-gateway

## Post-incident verification checklist

- New DIDs can be created (self-funded only).
- Anchors resume without backlog growth.
- Gateway onboarding can be re-enabled after validation.
