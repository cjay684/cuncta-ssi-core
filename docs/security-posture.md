# Security Posture

This page summarizes security boundaries, guarantees, and operator responsibilities for CUNCTA SSI Core.

## Security goals

- Preserve SSI semantics (SD-JWT, KB-JWT binding, policy-driven verification).
- Keep user private keys on the client side.
- Keep runtime services fail-fast in production.
- Minimize blast radius through least-privilege DB/service roles.

## Trust boundaries

- **Public edge:** `app-gateway` and selected public verifier/issuer endpoints.
- **Internal services:** did-service, issuer-service internals, verifier internals, policy-service internals.
- **Data plane:** Postgres with service-specific runtime roles and dedicated migration role.
- **External dependencies:** Hedera Testnet, issuer JWKS/status list fetches.

## Key guarantees

- Holder binding is always required in verifier (`KB-JWT`).
- Policy signatures are verified before policy enforcement.
- Policy version floor can prevent downgrade replay.
- Revocation is enforced via status list verification.
- DSR erase writes tombstones and blocks re-linkable processing.
- Production startup fails on unsafe configuration (examples below).

## Production fail-fast controls

- `AUTO_MIGRATE=true` in production -> startup failure.
- `STRICT_DB_ROLE=false` in production -> startup failure.
- `ALLOW_LEGACY_SERVICE_JWT_SECRET=true` in production -> startup failure.
- Optional strict internal transport mode:
  - `ENFORCE_HTTPS_INTERNAL=true` requires internal service URLs to be HTTPS.
- Verifier status-list fetch now enforces same-origin/path constraints to reduce SSRF risk.

## Public vs internal endpoint posture

- Public onboarding should be exposed through `app-gateway`.
- Admin issuance (`/v1/admin/issue`) requires service auth + admin scope.
- Public `/v1/issue` is disabled in production unless explicitly in dev mode.
- Testnet integration routes/tests remain opt-in via `RUN_TESTNET_INTEGRATION=1`.

## Supply-chain posture

- GitHub Actions are pinned to immutable SHAs.
- CI includes dependency audit, secret scanning, SBOM generation, and container scanning.
- Dependabot tracks npm and GitHub Actions updates.

## Not covered by code alone

- WAF/rate limiting at edge for internet-facing deployments.
- mTLS/service mesh enforcement in infrastructure.
- Secret rotation operations and key custody process.
- Network segmentation and self-hosted runner controls.

## Operator responsibilities

- Expose only intended public services/endpoints.
- Use service-specific DB roles in production.
- Run migrations as an explicit step using migration role credentials.
- Maintain key/secret rotation cadence and incident runbooks.
- Keep Testnet workflows and credentials scoped to approved runner environments.

## Related docs

- `docs/release-process.md`
- `docs/release-freeze-checklist.md`
- `docs/runbooks/README.md`
- `docs/runbooks/internal-transport-security.md`
- `docs/runbooks/self-hosted-runner-hardening.md`
