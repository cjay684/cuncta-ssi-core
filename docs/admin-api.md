# Admin API

The Admin API provides operational endpoints for service-to-service and operator use. **Not consumer-facing.**

All `/v1/admin/*` routes require service JWT authentication with either:

- `admin:*` scope (full admin access), or
- The specific scope listed for each endpoint

Requests without proper scope return `403` with `service_auth_scope_missing`.

## Endpoints

### Issuer Service

| Method | Path                          | Required Scope            | Description                                |
| ------ | ----------------------------- | ------------------------- | ------------------------------------------ |
| POST   | `/v1/admin/issue`             | `issuer:internal_issue`   | Issue credential (gateway onboarding flow) |
| POST   | `/v1/admin/keys/rotate`       | `issuer:key_rotate`       | Rotate issuer signing key                  |
| POST   | `/v1/admin/keys/revoke`       | `issuer:key_revoke`       | Revoke issuer key by `kid`                 |
| POST   | `/v1/admin/anchors/reconcile` | `issuer:anchor_reconcile` | Reconcile anchor outbox with Hedera mirror |
| GET    | `/v1/admin/privacy/status`    | `issuer:privacy_status`   | Get privacy status for subject DID hash    |

### Policy Service

| Method | Path                     | Required Scope     | Description                              |
| ------ | ------------------------ | ------------------ | ---------------------------------------- |
| POST   | `/v1/admin/policy/floor` | `policy:floor_set` | Set minimum policy version for an action |

## Usage

- Callers (e.g. app-gateway) use service JWT with appropriate scopes.
- Integration harness uses `createServiceToken` with issuer/policy audience and required scopes.
- For full admin access, include `admin:*` in the token scope.

## Not Consumer-Facing

These endpoints are for:

- Gateway → issuer (onboarding, issue)
- Internal services → issuer (privacy status)
- Operators (key rotation, anchor reconciliation, policy floor)
- Integration tests

Consumer flows use OID4VCI and OID4VP only.
