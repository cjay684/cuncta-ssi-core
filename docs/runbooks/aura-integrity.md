# Aura Integrity Runbook

Aura rules are signed using `POLICY_SIGNING_JWK` and anchored on change.

## Symptoms

- `aura_integrity_failed` in logs
- Aura worker halted
- `/v1/aura/claim` or `/v1/aura/explain` returns `503`

## Recovery Steps

1. Confirm `POLICY_SIGNING_JWK` and `ANCHOR_AUTH_SECRET` are set.
2. Set `POLICY_SIGNING_BOOTSTRAP=true` on issuer-service.
3. Restart issuer-service to re‑sign missing rules.
4. Verify `AURA_RULE_CHANGE` appears in `anchor_outbox`.
5. Confirm `anchor_receipts` include the new rule hash.
6. Set `POLICY_SIGNING_BOOTSTRAP=false` after recovery.
7. Restart issuer-service to resume aura worker.

## Validation

- Aura worker reports no errors in `/healthz`
- `audit_logs` include `aura_rule_change` entries
- `aura_rule_change_total` increases only on real changes

## Notes

- Invalid or missing signatures halt the aura worker by design.
- Verification and issuance continue even if aura is halted.
- Upgrades that modify `aura_rules.rule_logic` (including adding/adjusting capability `purpose` text) will invalidate existing rule signatures. Use the bootstrap flow to re-sign once, then disable bootstrap again.
