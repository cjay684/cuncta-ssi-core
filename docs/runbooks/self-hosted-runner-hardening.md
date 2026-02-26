# Self-Hosted Runner Hardening

Use this runbook for the Testnet integration runner.

## Minimum host hardening

- Use a dedicated host for CI runners (no shared user workloads).
- Keep OS and container runtime patched (automatic security updates enabled).
- Enable host firewall and default-deny inbound policy.
- Disable password SSH auth; require keys and MFA on control plane.
- Run runner with least privilege (non-admin user where possible).

## Secrets scope minimization

- Store secrets only in CI secret storage (never on disk in repo/workspace).
- Scope Testnet secrets to the integration workflow/environment only.
- Use separate secrets for runner bootstrap vs service runtime.
- Limit secret visibility to maintainers/operators, not all contributors.

## Network segmentation

- Place runner in a private subnet/VLAN.
- Allow outbound only to required endpoints (GitHub, package registry, Hedera Testnet, DB/service targets).
- Deny direct inbound access to internal services from public internet.
- Use egress filtering and DNS controls to reduce exfiltration paths.

## Ephemeral runner recommendation

- Prefer ephemeral runners that are destroyed after each job.
- If long-lived runners are required, reset workspace and container cache after each run.
- Rotate machine images regularly and rebuild from hardened templates.

## Secret rotation procedure

1. Rotate one secret at a time in secret manager/CI settings.
2. Re-run `testnet-integration` to validate new secret.
3. Remove old secret immediately after successful validation.
4. Record rotation in ops changelog with owner/date.

## Operational checklist before enabling workflow

- Host patched and rebooted into latest kernel/security baseline.
- Runner token rotation enabled and recent.
- Required secrets present and least-scoped.
- Outbound-only network policy validated.
- `RUN_TESTNET_INTEGRATION=1` remains workflow-only.
