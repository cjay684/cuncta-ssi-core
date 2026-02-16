# CUNCTA SSI Core

## Identities

- **Holder DID**: lives in `apps/wallet-cli/wallet-state.json` (wallet CLI). Used as `subjectDid`.
- **Issuer DID**: server-managed by issuer-service and bootstrapped via did-service. Stored in `apps/issuer-service/data/issuer-did.json`.
- These must be **different**. The issuer never reuses the holder DID.

## Why DIDs are not in .env

Infrastructure config belongs in `.env` (network, operator keys, base URLs, flags). DIDs are identity state, so they are created and stored at runtime:

- **Issuer DID**: generated from the server Hedera account and persisted in `apps/issuer-service/data/issuer-did.json`.
- **Holder DID**: created by the wallet CLI and stored in `apps/wallet-cli/wallet-state.json`.

## Strict flow

- Verifier issues per-request nonce/audience.
- Wallet creates a KB-JWT bound to nonce/audience and holder key.
- Verifier validates SD-JWT + KB-JWT and status list.
- `/v1/verify` always requires holder binding (KB-JWT); policy cannot disable it.

## Verifier helper (SDK)

Use `@cuncta/verifier-helper` to validate SD-JWTs, KB-JWT bindings, and status lists without
calling core services.

```ts
import {
  verifySdJwtPresentation,
  verifyKbJwtBinding,
  verifyStatusListEntry
} from "@cuncta/verifier-helper";

const sdResult = await verifySdJwtPresentation({
  presentation: sdJwtPresentation,
  issuerJwks
});
await verifyKbJwtBinding({
  kbJwt,
  audience,
  nonce,
  sdJwtPresentation
});
const statusCheck = await verifyStatusListEntry({
  status: sdResult.payload.status as Record<string, unknown>,
  issuerJwks,
  issuerBaseUrl: "https://issuer.example.com"
});
```

## Web demo

See `apps/web-demo` for a minimal frontend that demonstrates how applications integrate with CUNCTA SSI Core.
It is a demo/reference implementation, not a production wallet. In production posture, the demo uses
`app-gateway` for sponsor-paid onboarding so clients never hold service secrets.

## OpenAPI docs (baseline)

Minimal OpenAPI stubs live in `docs/openapi/`:

- `docs/openapi/did-service.yaml`
- `docs/openapi/issuer-service.yaml`
- `docs/openapi/verifier-service.yaml`
- `docs/openapi/policy-service.yaml`
- `docs/openapi/app-gateway.yaml`

## Architecture diagrams

See `docs/architecture.md` for Mermaid diagrams covering topology, verification flow, and DSR flow.

## Coverage plan

See `docs/coverage-plan.md` for the current thresholds and step-up plan.

## Release process

See `docs/release-process.md`.

## Onboarding strategies

Users can choose one of two onboarding modes without changing DID semantics or verification:

- **Sponsored**: app-gateway pays Hedera fees. Clients call gateway onboarding endpoints.
- **Self-funded**: users provide their own Hedera account to pay fees locally (private keys never leave client).

Config:

- `ONBOARDING_STRATEGY_DEFAULT` (`sponsored` or `user_pays`)
- `ONBOARDING_STRATEGY_ALLOWED` (comma list)
- `ALLOW_SPONSORED_ONBOARDING` (gateway kill switch)

Runbook: `docs/transition-sponsored-to-self-funded.md`.

## Testnet convenience: shared payer/sponsor account

For development, demos, and integration tests on Hedera Testnet only, the same account can be used
as both sponsor/operator and payer. This is a convenience to complete real Testnet proofs without
extra accounts.

Rules:

- Allowed only on Testnet.
- Blocked in production.
- Requires explicit opt-in (warning is logged once).
- Never use this on mainnet; production must separate payer and operator credentials.

## Quickstart (PowerShell)

```powershell
$env:DID_SERVICE_BASE_URL="http://localhost:3001"
$env:ISSUER_SERVICE_BASE_URL="http://localhost:3002"
$env:VERIFIER_SERVICE_BASE_URL="http://localhost:3003"
$env:POLICY_SERVICE_BASE_URL="http://localhost:3004"
$env:APP_GATEWAY_BASE_URL="http://localhost:3010"
$env:HEDERA_NETWORK="testnet"
$env:HEDERA_OPERATOR_ID="0.0.x"
$env:HEDERA_OPERATOR_PRIVATE_KEY="..."
$env:DEV_MODE="true"
```

Start all services + workers (issuer starts anchor + aura workers automatically):

```powershell
pnpm dev
```

Run full core smoke:

```powershell
pnpm --filter wallet-cli core:smoke
```

## Quickstart (bash)

```bash
export DID_SERVICE_BASE_URL="http://localhost:3001"
export ISSUER_SERVICE_BASE_URL="http://localhost:3002"
export VERIFIER_SERVICE_BASE_URL="http://localhost:3003"
export POLICY_SERVICE_BASE_URL="http://localhost:3004"
export APP_GATEWAY_BASE_URL="http://localhost:3010"
export HEDERA_NETWORK="testnet"
export HEDERA_OPERATOR_ID="0.0.x"
export HEDERA_OPERATOR_PRIVATE_KEY="..."
export DEV_MODE="true"
```

```bash
pnpm dev
pnpm --filter wallet-cli core:smoke
```

Run migrations explicitly (recommended for all environments):

```bash
pnpm migrate
```

## Required env

Base URLs:

- `APP_GATEWAY_BASE_URL`
- `DID_SERVICE_BASE_URL`
- `ISSUER_SERVICE_BASE_URL`
- `VERIFIER_SERVICE_BASE_URL`
- `POLICY_SERVICE_BASE_URL`

Hedera (network):

- `HEDERA_NETWORK=testnet|previewnet|mainnet`
- `HEDERA_OPERATOR_ID`
- `HEDERA_OPERATOR_PRIVATE_KEY`

Optional:

- `DEV_MODE=true` (enables dev-only aura action)
- `ALLOW_MAINNET=true` (required to run with `HEDERA_NETWORK=mainnet`)
- `ALLOW_INSECURE_DEV_AUTH=true` (dev-only; allowed only with loopback bind or `LOCAL_DEV=true`)
- `LOCAL_DEV=true` (explicitly allow insecure dev auth on non-loopback binds)
- `AUTO_MIGRATE` (dev default `true`, production default `false`; production fails if `true`)
- `MIGRATIONS_DATABASE_URL` (required in production for `pnpm migrate`; dev/test may fall back to `DATABASE_URL`)
- `STRICT_DB_ROLE` (defaults to `true` in production and `false` in dev/test)
- `ENFORCE_HTTPS_INTERNAL` (optional strict mode to require `https://` internal service URLs in production)
- `STATUS_LIST_CACHE_TTL_SECONDS` (verifier status list cache TTL, 1-60s)
- `STATUS_LIST_CACHE_MAX_ENTRIES` (verifier status list cache size, 8-1024)
- `STATUS_LIST_FETCH_TIMEOUT_MS` (verifier status list fetch timeout)
- `VERIFY_MAX_PRESENTATION_BYTES` (verifier max presentation size, default 65536)
- `VERIFY_MAX_NONCE_CHARS` (verifier max nonce length, default 256)
- `VERIFY_MAX_AUDIENCE_CHARS` (verifier max audience length, default 256)
- `VERIFY_MAX_DISCLOSURES` (verifier max disclosure count, default 100)
- `ANCHOR_MAX_ATTEMPTS` (issuer anchor outbox dead-letter threshold, default 25)
- `SERVICE_JWT_SECRET_FORMAT_STRICT=true` (require base64url/hex service secrets; defaults to true in prod)
- `PSEUDONYMIZER_*` (see "Pseudonymizer configuration" below)
- `APP_GATEWAY_BASE_URL` (if running the gateway)
- `GATEWAY_ALLOWED_VCTS` (comma-separated allowlist for onboarding issuance)
- `GATEWAY_VERIFY_DEBUG_REASONS` (gateway verify reason debug; never enable in production)
- `ALLOW_SELF_FUNDED_ONBOARDING` (enable gateway user-pays endpoints)
- `USER_PAYS_REQUEST_TTL_SECONDS` (self-funded request TTL, seconds)
- `USER_PAYS_MAX_TX_BYTES` (self-funded signed transaction size cap)
- `USER_PAYS_MAX_FEE_TINYBARS` (self-funded max fee cap)
- `USER_PAYS_HANDOFF_SECRET` (signing secret for user-pays handoff token)
- `GATEWAY_REQUIREMENTS_ALLOWED_ACTIONS` (comma-separated allowlist for /v1/requirements)
- `REQUIRE_DEVICE_ID_FOR_REQUIREMENTS` (require device id for /v1/requirements)
- `RATE_LIMIT_DEVICE_REQUIREMENTS_PER_MIN` (device rate limit for /v1/requirements)
- `CONTRACT_E2E_ENABLED` (enable contract-only admin routes; forbidden in production)
- `CONTRACT_E2E_ADMIN_TOKEN` (required when contract admin routes enabled)
- `CONTRACT_E2E_IP_ALLOWLIST` (comma-separated IP/CIDR allowlist for contract admin routes)
  - Supports IPv4, IPv6, and IPv4-mapped IPv6 (`::ffff:x.x.x.x`)
  - Does not support IPv4-embedded IPv6 (e.g. `2001:db8::192.0.2.1`)
  - Use pure IPv4 or IPv6 CIDRs for CI egress

Dynamic ports (optional):

- Set `DYNAMIC_PORTS=1` to auto-allocate free localhost ports when `*_BASE_URL` values are not provided.
- You may also override ports directly via `DID_SERVICE_PORT`, `ISSUER_SERVICE_PORT`, `VERIFIER_SERVICE_PORT`,
  `POLICY_SERVICE_PORT`, and `APP_GATEWAY_PORT`.

## Bootstrap dev checklist

- Set base URLs + `HEDERA_NETWORK=testnet` (or previewnet/mainnet with `ALLOW_MAINNET=true`).
- Provide `HEDERA_OPERATOR_ID` + `HEDERA_OPERATOR_PRIVATE_KEY`.
- Set `PSEUDONYMIZER_PEPPER` and `SERVICE_JWT_SECRET`.
- Start services with `pnpm dev`, then run `pnpm --filter wallet-cli core:smoke`.

## Testnet integration verification suite

These tests are opt-in and hit real Hedera Testnet and real services. They are slower
and incur testnet costs. No mocks are used.

Modes:

- Direct mode (default): services called directly.
- Gateway mode (`GATEWAY_MODE=1`): run onboarding via `app-gateway` and proxy `/v1/verify`.
- User-pays mode (`USER_PAYS_MODE=1`): create DIDs locally with payer creds (no did-service create/submit).

Commands:

- Direct mode: `RUN_TESTNET_INTEGRATION=1 pnpm verify:testnet`
- Gateway mode: `RUN_TESTNET_INTEGRATION=1 GATEWAY_MODE=1 pnpm verify:testnet`
- User-pays mode: `RUN_TESTNET_INTEGRATION=1 USER_PAYS_MODE=1 pnpm verify:testnet`

Required open ports:

- `3001` (did-service)
- `3002` (issuer-service)
- `3003` (verifier-service)
- `3004` (policy-service)
- `3010` (app-gateway, gateway mode only)

Expected runtime:

- 8–15 minutes depending on Testnet responsiveness (slowest steps: DID visibility, anchor confirmations, cache TTL wait).

Testnet eventual consistency:

- DID create submit is async on Testnet: `/v1/dids/create/submit` returns immediately with `visibility: "pending"`.
- Clients should poll `/v1/dids/resolve/:did` until visible (no transaction resubmits).
- To preserve the old behavior, pass `waitForVisibility=true` on submit; default is `false` on Testnet.
- The harness configures child services to use the full visibility budget.
- If visibility still fails, the harness prints the DID, elapsed time, and last resolver error, then fails.
- Did-service metrics (Prometheus) for Testnet latency monitoring.
- `did_resolution_poll_total`: total resolve polls served.
- `did_resolution_success_total`: polls that returned a non-empty DID document.
- `did_resolution_timeout_total`: resolver timeouts (error messages containing "timeout"/"exceeded").
- `did_resolution_last_elapsed_ms`: last resolver call duration in ms (not end-to-end visibility time).

CI guidance (optional):

- Run only on a self-hosted runner with secrets configured.
- For GitHub Actions, use the manual Testnet workflow and keep secrets in repo settings.

Secrets hygiene:

- Do not commit real keys or JWKS into the repo.
- `.env` is ignored; `.env.example` contains placeholders only.
- Wallet state is generated locally by `wallet-cli` and should never be committed.

Required env:

- `HEDERA_NETWORK=testnet|previewnet|mainnet`
- `HEDERA_OPERATOR_ID`
- `HEDERA_OPERATOR_PRIVATE_KEY`
- `DID_SERVICE_BASE_URL`
- `ISSUER_SERVICE_BASE_URL`
- `VERIFIER_SERVICE_BASE_URL`
- `POLICY_SERVICE_BASE_URL`
- `ISSUER_BASE_URL`
- `DATABASE_URL`
- `PSEUDONYMIZER_PEPPER`
- `SERVICE_JWT_SECRET`

Service JWT secrets must be at least 32 characters. Recommended format: base64url (>=43 chars) or hex (>=64 chars).

Optional:

- `SERVICE_JWT_AUDIENCE` (defaults to `cuncta-internal`)
- `SERVICE_JWT_AUDIENCE_DID` (defaults to `cuncta.service.did`)
- `SERVICE_JWT_AUDIENCE_ISSUER` (defaults to `cuncta.service.issuer`)
- `SERVICE_JWT_AUDIENCE_VERIFIER` (defaults to `cuncta.service.verifier`)
- `HEDERA_ANCHOR_TOPIC_ID` (auto-created if unset)
- `STATUS_LIST_CACHE_TTL_SECONDS`
- `STATUS_LIST_FETCH_TIMEOUT_MS`
- `DEV_MODE=true` (required for dev-only aura signal test)
- `SPONSOR_MAX_DID_CREATES_PER_DAY` (defaults to `500`)
- `SPONSOR_MAX_ISSUES_PER_DAY` (defaults to `2000`)
- `SPONSOR_KILL_SWITCH` (defaults to `false`)
- `HEDERA_PAYER_ACCOUNT_ID` + `HEDERA_PAYER_PRIVATE_KEY` (required when `USER_PAYS_MODE=1`)
- Testnet-only fallback (dev/demo): if `HEDERA_PAYER_*` is missing and `HEDERA_NETWORK=testnet`,
  the operator creds may be used as payer with a warning. This is disabled in production.
- `DID_RESOLVE_MAX_ATTEMPTS` (integration polling attempts, default 240, clamped)
- `DID_RESOLVE_INTERVAL_MS` (integration polling interval, default 5000, clamped)
- `DID_VISIBILITY_TOTAL_TIMEOUT_MS` (overall DID visibility budget, default 1,200,000 ms, clamped)

Example `.env` snippet (placeholders):

```
HEDERA_NETWORK=testnet
HEDERA_OPERATOR_ID=0.0.x
HEDERA_OPERATOR_PRIVATE_KEY=...
APP_GATEWAY_BASE_URL=http://localhost:3010
DID_SERVICE_BASE_URL=http://localhost:3001
ISSUER_SERVICE_BASE_URL=http://localhost:3002
VERIFIER_SERVICE_BASE_URL=http://localhost:3003
POLICY_SERVICE_BASE_URL=http://localhost:3004
ISSUER_BASE_URL=http://localhost:3002
DATABASE_URL=postgres://cuncta:cuncta@localhost:5432/cuncta_ssi
PSEUDONYMIZER_PEPPER=change-me
SERVICE_JWT_SECRET=change-me-please-use-32-characters-minimum
SERVICE_JWT_AUDIENCE_DID=cuncta.service.did
SERVICE_JWT_AUDIENCE_ISSUER=cuncta.service.issuer
SERVICE_JWT_AUDIENCE_VERIFIER=cuncta.service.verifier
DEV_MODE=true
GATEWAY_ALLOWED_VCTS=cuncta.marketplace.seller_good_standing
ISSUER_INTERNAL_ALLOWED_VCTS=cuncta.marketplace.seller_good_standing
```

Warning: these tests create real DIDs on Hedera testnet and may take 1–3 minutes.

Note: `ISSUER_JWKS` must be unset/empty for the integration suite so verifier
fetches real JWKS from issuer-service.

Run:

```bash
pnpm verify:testnet
```

or

```bash
pnpm test:integration
```

Example opt-in invocation:

PowerShell:

```powershell
$env:RUN_TESTNET_INTEGRATION="1"
pnpm test:integration
```

Bash:

```bash
RUN_TESTNET_INTEGRATION=1 pnpm test:integration
```

This will hit real Hedera Testnet and may take a few minutes.

## Contract E2E suite (gateway-only)

Contract tests validate oracle-resistance, replay resistance, and rotation guardrails
against a deployed staging gateway on Testnet. The suite only calls `APP_GATEWAY_BASE_URL`
over HTTP(S) and runs real cryptographic flows.

Run:

```bash
RUN_TESTNET_INTEGRATION=1 HEDERA_NETWORK=testnet APP_GATEWAY_BASE_URL=https://staging-gateway.example pnpm test:contract:e2e
```

Rotation guard tests (local Docker):

```bash
pnpm test:contract:guards
```

## Gateway capabilities endpoint

`GET /v1/capabilities` exposes minimal, non-sensitive integration flags for wallets.

Response (example):

```json
{
  "selfFundedOnboarding": {
    "enabled": true,
    "maxFeeTinybars": 50000000,
    "maxTxBytes": 8192,
    "requestTtlSeconds": 60
  },
  "network": "testnet",
  "requirements": { "requireDeviceId": false }
}
```

Guarantees:

- No secrets or PII.
- Stable fields; additive-only changes.
- Intended for lightweight client boot-time checks (cache briefly).

Contract suite requires a staging gateway with contract admin routes enabled:

- `CONTRACT_E2E_ENABLED=true`
- `CONTRACT_E2E_ADMIN_TOKEN` set (used by the suite for revoke)
- Optional `CONTRACT_E2E_IP_ALLOWLIST` for CI egress IPs

## DB-dependent unit tests

Some service unit tests hit Postgres (policy evaluation, verifier guardrails, issuer flows).
They are skipped by default and are opt-in:

- Default: `pnpm -C apps/verifier-service test` (skips DB-dependent tests)
- Opt-in: `RUN_DB_TESTS=1 pnpm -C apps/verifier-service test`

When `RUN_DB_TESTS=1` is set, `DATABASE_URL` must be present (via `.env` or env var)
or the runner exits with a clear error. Ensure CI has a dedicated DB-enabled job so
these tests do not silently rot.

## Pseudonymizer configuration

- `PSEUDONYMIZER_PEPPER`:
  - Required in production (services refuse startup if missing).
  - In dev/test, if missing a random in-memory pepper is generated (hashes will change each restart).
- `PSEUDONYMIZER_ALLOW_LEGACY`:
  - Defaults true in dev/test, false in production.
  - When true, reads match both legacy SHA-256 hashes and new HMAC hashes; new writes always use HMAC.
  - Enabling legacy in production is discouraged.

## Commands (PowerShell)

Start all services + workers (issuer starts anchor + aura workers automatically):

```powershell
pnpm dev
```

## App gateway (public onboarding)

The gateway exposes public onboarding endpoints and mints service JWTs internally. Clients never
hold `SERVICE_JWT_SECRET`.

Start gateway:

```powershell
pnpm -C apps/app-gateway dev
```

Start web demo:

```powershell
pnpm -C apps/web-demo dev
```

## Production posture (summary)

Sponsor-paid onboarding must not be publicly exposed from core services. Use `app-gateway`:

- Public onboarding routes: gateway only.
- did-service / issuer-service: internal only, service-auth in production.
- verifier `/v1/verify`: can be public but must be rate-limited (gateway or WAF).

TLS termination and CORS are handled at the edge. Services do not enable CORS by default, so
configure HTTPS/TLS and any required CORS policies in your ingress or gateway layer.
For container deployments, ensure service bind addresses remain private and are only exposed
via the ingress or reverse proxy layer.

## Production safety envs

These guardrails make mis-segmentation and proxy misconfig fail fast in production.

- `SERVICE_BIND_ADDRESS`: must be private (loopback, RFC1918, or ULA); public/unspecified binds fail in production.
- `PUBLIC_SERVICE`: only `app-gateway` may be public; other services fail startup if `PUBLIC_SERVICE=true` in prod.
- `TRUST_PROXY`: required in prod; startup fails if `false`.
- `SERVICE_JWT_SECRET_NEXT`: dual-secret validation for rotation; rotate by deploying internal services with both,
  then switch gateway to mint the new secret, then remove the old secret.
- `ISSUER_JWKS`: must be unset in production; verifier fails startup if set.
- `BACKUP_RESTORE_MODE`: when true, onboarding/issuance/verification/DSR return `503` during restores.
- `PSEUDONYMIZER_ALLOW_LEGACY`: prohibited in production (startup fails if enabled).
- `ALLOW_LEGACY_SERVICE_JWT_SECRET`: prohibited in production (startup fails if enabled).
- `AUTO_MIGRATE`: prohibited in production (`auto_migrate_not_allowed_in_production`).
- `STRICT_DB_ROLE=false`: prohibited in production (`strict_db_role_required_in_production`).

Example `.env` snippet (recommended prod posture, no secrets):

```
NODE_ENV=production
SERVICE_BIND_ADDRESS=127.0.0.1
PUBLIC_SERVICE=false
TRUST_PROXY=true
SERVICE_JWT_SECRET_NEXT=
ISSUER_JWKS=
BACKUP_RESTORE_MODE=false
AUTO_MIGRATE=false
STRICT_DB_ROLE=true
ENFORCE_HTTPS_INTERNAL=true
```

Expose only app-gateway publicly; keep all other services private.
See `docs/runbooks/README.md` for incident response and chaos checks, and
`docs/runbooks/internal-transport-security.md` for HTTPS/mTLS deployment guidance.
For release hardening and trust-boundary posture, see
`docs/release-freeze-checklist.md` and `docs/security-posture.md`.

## Production safety guarantees

- Startup fails on unsafe public bindings, proxy misconfig, or prohibited dev flags.
- `/v1/verify` always requires holder binding (KB-JWT), independent of policy.
- Audit logs are chained and periodically anchored for tamper evidence.
- Aura rules are signed and anchored; invalid rules halt aura processing.
- Backup/restore mode blocks high‑risk endpoints until integrity checks pass.

## What the system does NOT protect against

- A compromised policy signing key (requires immediate rotation and re‑signing).
- Full DB compromise without restoring from a trusted backup.
- Mis-segmentation that exposes internal services to the public internet.
- Operators who disable monitoring, backups, or secret rotation.

## Operator responsibilities

- Keep internal services private; expose only app-gateway publicly.
- Use a secret manager for all signing keys and service JWT secrets.
- Monitor anchor worker health, audit head freshness, and budget metrics.
- Use `BACKUP_RESTORE_MODE` during restore procedures.
- Rotate keys on compromise using the runbooks.

## Mixed-version deployment safety

- **Service JWT rotation**: deploy internal services with `SERVICE_JWT_SECRET` + `SERVICE_JWT_SECRET_NEXT`,
  then update gateway to mint the new secret, then remove the old secret from all services.
- **Gateway upgrade**: update internal services first when auth or request formats change; then gateway.
- **Verifier upgrade**: update verifier before policy changes that introduce new requirements.
- Supported skew window: one version step (avoid skipping multiple releases).

### Endpoint posture matrix

| Endpoint                                          | Public/Internal | Auth               | Rate limit           | Sensitivity | Logs      |
| ------------------------------------------------- | --------------- | ------------------ | -------------------- | ----------- | --------- |
| app-gateway `POST /v1/onboard/did/create/request` | Public          | None (gateway)     | strict per IP/device | Medium      | hash-only |
| app-gateway `POST /v1/onboard/did/create/submit`  | Public          | None (gateway)     | strict per IP/device | High (fees) | hash-only |
| app-gateway `POST /v1/onboard/issue`              | Public          | None (gateway)     | strict per IP/device | High        | hash-only |
| did-service `/v1/dids/create/*`                   | Internal        | Service JWT        | n/a                  | High (fees) | hash-only |
| issuer-service `/v1/internal/issue`               | Internal        | Service JWT        | n/a                  | High        | hash-only |
| issuer-service `/v1/issue`                        | Dev/demo only   | None               | n/a                  | High        | hash-only |
| issuer-service `/jwks.json`                       | Public          | None               | cache                | Low         | ok        |
| issuer-service `/status-lists/*`                  | Public          | None               | cache                | Low         | ok        |
| verifier-service `/v1/verify`                     | Public          | None               | strict               | Medium      | hash-only |
| privacy endpoints                                 | Public          | DSR token / KB-JWT | strict               | High        | hash-only |

Edge header normalization (at ingress/WAF):

- Normalize `X-Forwarded-For` to a single client IP and drop spoofed values.
- Require `X-Request-Id` (generate at edge if missing).
- Validate `X-Device-Id` format before forwarding to app-gateway.

Health + metrics:

```powershell
curl http://localhost:3002/healthz
curl http://localhost:3002/metrics
```

Smoke tests:

```powershell
pnpm --filter wallet-cli core:smoke
pnpm --filter wallet-cli smoke
pnpm --filter wallet-cli smoke:full
pnpm --filter wallet-cli smoke:strict
```

Aura demo (wallet CLI):

```powershell
pnpm --filter wallet-cli issue:request
pnpm --filter wallet-cli exec -- tsx src/cli.ts aura:simulate dev.aura.signal 2
pnpm --filter wallet-cli exec -- tsx src/cli.ts aura:claim cuncta.marketplace.seller_good_standing
```

Note: `dev.aura.signal` is available only when `DEV_MODE=true` and is not present in production.
Dev-only routes under `/v1/dev/*` require `NODE_ENV=development`, `DEV_MODE=true`, and either a loopback bind or a service token with scope `issuer:dev_issue`.

## Troubleshooting

- Postgres not running: start Docker Desktop and run `docker compose up -d`.
- Hedera operator misconfigured: ensure `HEDERA_OPERATOR_ID` + `HEDERA_OPERATOR_PRIVATE_KEY` are set.
- JWKS fetch failing: verify `ISSUER_SERVICE_BASE_URL` and that issuer-service is running.
- Aura not ready: queue is populated only after successful verification obligations run.
- Anchoring pending: issuance/verification succeed even if anchor worker is down; receipts will confirm once HCS is reachable.

## We do NOT store

- Raw SD-JWT tokens
- Raw presentations
- Raw credential claims
- PII

## Storage limitation

Core storage is hashes/indices/timestamps only (no raw tokens, presentations, claims, or PII). Default retention
windows are configurable: verification challenges (7 days), rate limit events (7 days), obligation events (30 days),
aura signals (90 days), audit logs (90 days). Cleanup deletes expired/consumed `verification_challenges` plus the
telemetry tables above. It does NOT delete status lists, issuance events required for revocation correctness, or
anchor receipts/outbox. On-chain HCS anchors are immutable; retention applies only to off-chain telemetry. Retention
knobs live in `.env.example` (PowerShell: `$env:RETENTION_VERIFICATION_CHALLENGES_DAYS="7"`; bash:
`export RETENTION_VERIFICATION_CHALLENGES_DAYS="7"`).

## Data subject rights (DSR)

DSR uses proof-of-control of the holder DID and stays hash-only (no PII, no raw tokens, no raw claims). Export returns
hash-only records: issuance events, revocation references, obligation telemetry summaries, aura state, and linked anchor
receipts (where available). Restrict flags stop further Aura/obligation processing while keeping core verification
semantics intact. Erase/unlink removes off-chain linkable state and sets a tombstone; on-chain HCS anchors remain
immutable. Retention and privacy knobs live in `.env.example` (PowerShell: `$env:PRIVACY_TOKEN_TTL_SECONDS="900"`; bash:
`export PRIVACY_TOKEN_TTL_SECONDS="900"`). See `docs/threat-model.md` for details.

DSR flow (PowerShell):

```powershell
$env:ISSUER_SERVICE_BASE_URL="http://localhost:3002"
curl -s -X POST "$env:ISSUER_SERVICE_BASE_URL/v1/privacy/request" -H "content-type: application/json" -d "{\"did\":\"did:hedera:testnet:...\"}"
pnpm --filter wallet-cli privacy:kbjwt --requestId <id> --nonce <nonce> --audience cuncta.privacy:request
curl -s -X POST "$env:ISSUER_SERVICE_BASE_URL/v1/privacy/confirm" -H "content-type: application/json" -d "{\"requestId\":\"<id>\",\"nonce\":\"<nonce>\",\"kbJwt\":\"<kbJwt>\"}"
curl -s "$env:ISSUER_SERVICE_BASE_URL/v1/privacy/export" -H "authorization: Bearer <dsrToken>"
curl -s -X POST "$env:ISSUER_SERVICE_BASE_URL/v1/privacy/restrict" -H "authorization: Bearer <dsrToken>" -H "content-type: application/json" -d "{\"reason\":\"user request\"}"
curl -s -X POST "$env:ISSUER_SERVICE_BASE_URL/v1/privacy/erase" -H "authorization: Bearer <dsrToken>" -H "content-type: application/json" -d "{\"mode\":\"unlink\"}"
```

DSR flow (bash):

```bash
export ISSUER_SERVICE_BASE_URL="http://localhost:3002"
curl -s -X POST "$ISSUER_SERVICE_BASE_URL/v1/privacy/request" -H "content-type: application/json" -d '{"did":"did:hedera:testnet:..."}'
pnpm --filter wallet-cli privacy:kbjwt --requestId <id> --nonce <nonce> --audience cuncta.privacy:request
curl -s -X POST "$ISSUER_SERVICE_BASE_URL/v1/privacy/confirm" -H "content-type: application/json" -d '{"requestId":"<id>","nonce":"<nonce>","kbJwt":"<kbJwt>"}'
curl -s "$ISSUER_SERVICE_BASE_URL/v1/privacy/export" -H "authorization: Bearer <dsrToken>"
curl -s -X POST "$ISSUER_SERVICE_BASE_URL/v1/privacy/restrict" -H "authorization: Bearer <dsrToken>" -H "content-type: application/json" -d '{"reason":"user request"}'
curl -s -X POST "$ISSUER_SERVICE_BASE_URL/v1/privacy/erase" -H "authorization: Bearer <dsrToken>" -H "content-type: application/json" -d '{"mode":"unlink"}'
```

Note: `privacy:kbjwt` is a dev/testing helper. Production apps should mint KB-JWTs inside the client wallet. See
`docs/threat-model.md` for storage limitation and immutable anchor details. For local testing, you can use
`privacy:flow` to exercise the full DSR lifecycle; production apps must implement this flow in their own
wallet/client. See `docs/compliance.md` for a concise compliance posture overview.

## Core invariants

- Mainnet is opt-in only (`ALLOW_MAINNET=true` required)
- No raw tokens/presentations/claims storage columns
- No request logging of bodies/headers
- No JWT-like strings in stored hashes
