# Database Roles (Least Privilege)

Production should use separate DB roles per service instead of one shared `DATABASE_URL`.

## Roles

- `db_role_gateway`: sponsor budget tables only
- `db_role_policy`: policy and challenge lifecycle tables
- `db_role_verifier`: verify read/write obligations and rate-limit side effects
- `db_role_issuer`: issuance/revocation/aura/privacy/anchor tables
- `db_role_migrations`: schema migration role

Use `docs/db-roles.sql` as the baseline grant script.

## Migration step is separate from runtime

- Migrations run with `db_role_migrations` only.
- Runtime services must not run migrations in production.
- Use `pnpm migrate` before starting/upgrading services.

## Service wiring (example)

Use distinct credentials in deployment secrets:

- `app-gateway`: `DATABASE_URL=postgres://db_role_gateway:<pw>@db:5432/cuncta_ssi`
- `policy-service`: `DATABASE_URL=postgres://db_role_policy:<pw>@db:5432/cuncta_ssi`
- `verifier-service`: `DATABASE_URL=postgres://db_role_verifier:<pw>@db:5432/cuncta_ssi`
- `issuer-service`: `DATABASE_URL=postgres://db_role_issuer:<pw>@db:5432/cuncta_ssi`
- migration job: `MIGRATIONS_DATABASE_URL=postgres://db_role_migrations:<pw>@db:5432/cuncta_ssi`

Local development can continue using a single privileged role.

## Runtime guardrails

- `STRICT_DB_ROLE` defaults to true in production and false in dev/test.
- Production startup fails if `STRICT_DB_ROLE=false` (`strict_db_role_required_in_production`).
- Strict mode probes forbidden tables using read checks plus a no-op write probe with rollback, and fails startup on unexpected write permissions.
