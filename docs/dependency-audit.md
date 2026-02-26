# Dependency Audit Triage

This document tracks `pnpm audit` findings and the decision for each advisory.

## How to update

1. Run `pnpm audit --audit-level high`.
2. For each advisory, record:
   - Package + version
   - Advisory ID / URL
   - Severity
   - Status: accept / fix / mitigated
   - Notes (why, impact, mitigation)

## CI policy (blocking)

- CI runs `pnpm audit --audit-level high` and blocks on unresolved high/critical findings.
- Do not bypass audit failures in CI; either fix, or document and suppress with explicit ownership.

## Suppression workflow

1. Confirm the advisory is a false positive, not reachable, or already mitigated by runtime controls.
2. Add a note in this document with:
   - package/version
   - advisory ID
   - business/technical rationale
   - owner and expiry/revisit date
3. Apply a technical suppression only if unavoidable:
   - use `pnpm.overrides` to pin a safe transitive version, or
   - temporarily ignore in tooling with a tracked follow-up issue.
4. Remove suppression after upstream remediation is available.
