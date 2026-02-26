# Database Migrations

## Principle

- Runtime services use least-privilege DB roles and should not perform schema migrations in production.
- Execute migrations as an explicit operational step with `db_role_migrations`.

## Command

```bash
pnpm migrate
```

Environment variables:

- `MIGRATIONS_DATABASE_URL` (required in production)
- fallback: `DATABASE_URL`

## Production guardrails

- `AUTO_MIGRATE` defaults to `false` in production.
- Startup fails with `auto_migrate_not_allowed_in_production` when `AUTO_MIGRATE=true` in production.
- Migration command fails in production when `MIGRATIONS_DATABASE_URL` is unset
  (`migrations_database_url_required_in_production`).

## Suggested rollout order

1. Run migrations (`pnpm migrate`) using migration role.
2. Deploy services with runtime least-privilege roles.
3. Verify health endpoints and strict DB role checks.
