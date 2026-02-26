# API Surfaces (Human Reference)

This doc is a human-readable reference for what is:

- Consumer/public API surface (external customers)
- Operator/admin API surface (`/v1/admin/*`)
- Private/internal service surfaces (must not be exposed directly)

Canonical source of truth (used by runtime enforcement + CI gates):

- `docs/surfaces.registry.json`

## Surface Registry Integrity Model

`docs/surfaces.registry.json` is treated as security-critical configuration. The runtime services that enforce public surfaces (`app-gateway`, `issuer-service`) verify the integrity of the registry before serving traffic.

- Signed bundle: `docs/surfaces.registry.bundle.json`
- Signature algorithm: JWS (EdDSA / Ed25519), covering the canonicalized registry JSON
- Production posture (`NODE_ENV=production` + `PUBLIC_SERVICE=true`):
  - Load + verify the bundle at startup
  - If missing/invalid/unsigned/tampered or verification fails, the service aborts startup with `surface_registry_integrity_failed`
- Non-production:
  - Unsigned `docs/surfaces.registry.json` is allowed (developer ergonomics)
  - If the bundle is missing or can’t be verified, services log a loud warning and continue

Key generation, signing, and rotation procedures live in `docs/runbooks/surface-registry-signing.md`.

## Consumer (Public) Surface

Public entrypoint is `app-gateway` only.

### app-gateway

- OID4VP (canonical consumer verification)
  - `GET /oid4vp/authorize`
  - `GET /oid4vp/request`
  - `GET /oid4vp/request_uri`
  - `POST /oid4vp/response`
  - `GET /.well-known/jwks.json` (verifier request-signing JWKS, proxied)
- OID4VCI (wallet-first credential acquisition)
  - `GET /oid4vci/offer`
  - `GET /oid4vci/aura/challenge`
  - `POST /oid4vci/aura/offer`
- Self-funded onboarding (no sponsorship)
  - `POST /v1/onboard/did/create/user-pays/request`
  - `POST /v1/onboard/did/create/user-pays/submit`
- DID resolution (proxy)
  - `GET /v1/dids/resolve/:did`
- Health/metrics
  - `GET /healthz`
  - `GET /metrics`

- Gateway public API (product surfaces)
  - Capabilities / posture
    - `GET /v1/capabilities`
  - Requirements (policy request surface)
    - `GET /v1/requirements`
  - Verification (legacy adapter; public but returns normalized DENY on verifier dependency failures)
    - `POST /v1/verify`
  - Command surfaces
    - `POST /v1/command/plan`
  - Realtime surfaces
    - `GET /v1/realtime/*`
    - `POST /v1/realtime/*`
  - Media surfaces
    - `POST /v1/media/*`
  - Social surfaces
    - `GET /v1/social/*`
    - `POST /v1/social/*`

- Deprecated onboarding surfaces (reachable but hard-disabled in production)
  - `POST /v1/onboard/did/create/request` (410 in production posture)
  - `POST /v1/onboard/did/create/submit` (410 in production posture)
  - `POST /v1/onboard/issue` (410 in production posture)
  - `POST /v1/onboard/revoke` (gated by contract-e2e + IP allowlist; not a consumer surface)

### issuer-service (public metadata + OID4VCI)

- OID4VCI
  - `GET /.well-known/openid-credential-issuer`
  - `POST /token`
  - `POST /credential`
- Public verification material
  - `GET /jwks.json`
  - `GET /status-lists/*`
- Public metadata/catalog
  - `GET /v1/issuer`
  - `GET /v1/catalog/credentials`
  - `GET /v1/catalog/credentials/:vct`
- Privacy / DSR (public, bearer-token protected where applicable)
  - `POST /v1/privacy/request`
  - `POST /v1/privacy/confirm`
  - `GET /v1/privacy/export`
  - `POST /v1/privacy/restrict`
  - `POST /v1/privacy/erase`
  - `GET /v1/privacy/erase-status`
- Health/metrics
  - `GET /healthz`
  - `GET /metrics`

### issuer-service (internal capability issuance)

- Internal/dev convenience (must not be exposed publicly):
  - `POST /v1/aura/claim` (service-auth; internal portability shortcut, not the consumer path)
  - `GET /v1/aura/explain` (service-auth)
  - `POST /v1/issue` (service-auth)
  - `POST /v1/revoke` (service-auth)
  - `POST /v1/credentials/revoke` (service-auth)
  - `POST /v1/reputation/events` (service-auth)
  - `POST /v1/reputation/recompute/:did` (service-auth)
  - `POST /v1/internal/oid4vci/*` (service-auth; gateway proxies public OID4VCI surfaces)

## Operator / Admin Surface (`/v1/admin/*`)

All admin routes require service JWT auth with either `admin:*` or the specific scope.

### issuer-service

- `POST /v1/admin/issue` (`issuer:internal_issue`)
- `POST /v1/admin/keys/rotate` (`issuer:key_rotate`)
- `POST /v1/admin/keys/revoke` (`issuer:key_revoke`)
- `POST /v1/admin/anchors/reconcile` (`issuer:anchor_reconcile`)
- `GET /v1/admin/privacy/status` (`issuer:privacy_status`)
- Aura admin/debug
  - `GET /v1/admin/aura/explain` (`issuer:aura_explain`)
  - `POST /v1/admin/aura/reset` (`issuer:aura_reset`)

### issuer-service (dev/test only)

- `POST /v1/dev/issue` (dev only; must be disabled in production)

### policy-service

- `POST /v1/admin/policy/floor` (`policy:floor_set`)

Full details and examples: `docs/admin-api.md`.

## Private (Must Not Be Public)

These services are intended to run on a private network behind the gateway:

- `did-service`
- `verifier-service`
- `policy-service`
- internal portions of `issuer-service`

They may expose some unauthenticated endpoints for internal topology (health/metrics), but they must not be internet-exposed in production.

## OpenAPI References

OpenAPI stubs live in `docs/openapi/` and should be read through the lens of this surface map:

- Public/consumer-facing:
  - `docs/openapi/app-gateway.yaml`
  - `docs/openapi/issuer-service.yaml` (OID4VCI + public metadata)
- Private/internal or admin/operator-facing:
  - `docs/openapi/verifier-service.yaml` (private behind gateway; includes deprecated legacy routes)
  - `docs/openapi/did-service.yaml` (service-auth create; resolve is safe to proxy via gateway)
  - `docs/openapi/policy-service.yaml` (requirements are internal; gateway is the consumer surface)

