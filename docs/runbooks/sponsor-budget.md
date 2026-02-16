# Sponsor Budget Runbook

Gateway sponsor limits now use reservation semantics:

1. Reserve budget (`RESERVED`) before downstream sponsor operation.
2. Commit reservation (`COMMITTED`) only after downstream success.
3. Revert reservation (`REVERTED`) on downstream failure.

This prevents sponsor budget burn when DID submit or internal issue fails.

## Metrics

- `sponsor_budget_reserved_total`
- `sponsor_budget_committed_total`
- `sponsor_budget_reverted_total`
- `sponsor_budget_commit_fail_total`

## Operational checks

- If `sponsor_budget_commit_fail_total` increases, investigate DB availability/lock contention.
- If `sponsor_budget_reverted_total` spikes, investigate downstream DID/issuer failures.
- Use `sponsor_budget_daily` for committed counts only, and `sponsor_budget_events` for reservation lifecycle.
