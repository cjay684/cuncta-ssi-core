# Architecture

## Service Topology

```mermaid
flowchart LR
  wallet[Wallet / Client] -->|HTTPS (public)| gw[app-gateway]

  gw -->|service JWT (private)| did[did-service]
  gw -->|service JWT (private)| issuer[issuer-service]
  gw -->|service JWT (private)| verifier[verifier-service]
  gw -->|service JWT (private)| policy[policy-service]

  did --> db[(Postgres)]
  issuer --> db
  verifier --> db
  policy --> db

  did -->|Hiero DID registrar/resolver| hedera[(Hedera HCS)]
  issuer -->|Anchors / audit / receipts| hedera
  did --> mirror[Hedera Mirror Node]
  issuer --> mirror
```

## Verification Flow

```mermaid
sequenceDiagram
  participant Wallet
  participant Gateway as app-gateway
  participant Policy as policy-service
  participant Verifier as verifier-service
  participant Issuer as issuer-service

  Wallet->>Gateway: GET /oid4vp/request?action=...
  Gateway->>Policy: GET /v1/requirements?action=...&verifier_origin=<gateway-origin>
  Policy-->>Gateway: requirements + nonce + origin-scoped audience
  Gateway->>Verifier: POST /v1/request/sign (service JWT)
  Verifier-->>Gateway: request_jwt (EdDSA)
  Gateway-->>Wallet: OID4VP request object + request_jwt

  Wallet->>Gateway: GET /.well-known/jwks.json (derived from request_jwt.iss)
  Gateway-->>Wallet: JWKS (verifier signing key)

  Wallet->>Gateway: POST /oid4vp/response (SD-JWT presentation + KB-JWT)
  Gateway->>Verifier: POST /oid4vp/response (proxy)
  Verifier->>Issuer: GET /jwks.json (credential signing + status list keys)
  Verifier->>Policy: POST /v1/policy/evaluate
  Verifier-->>Gateway: decision + reasons
  Gateway-->>Wallet: decision (+ optional debug reasons)
```

## DSR Flow (Privacy)

```mermaid
sequenceDiagram
  participant Client
  participant Issuer
  participant DB
  Client->>Issuer: POST /v1/privacy/restrict
  Issuer->>DB: record restriction
  Client->>Issuer: POST /v1/privacy/erase
  Issuer->>DB: tombstone + redact
  Client->>Issuer: GET /v1/privacy/export
  Issuer-->>Client: export token + dataset
```
