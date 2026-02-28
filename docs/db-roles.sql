-- CUNCTA SSI Core least-privilege DB roles
-- Use in production with separate DATABASE_URL per service.
-- Migrations must run only with db_role_migrations credentials.

-- Replace these placeholders before applying:
--   <db_name>
--   <gateway_password>
--   <policy_password>
--   <verifier_password>
--   <issuer_password>
--   <migrations_password>

create role db_role_gateway login password '<gateway_password>';
create role db_role_policy login password '<policy_password>';
create role db_role_verifier login password '<verifier_password>';
create role db_role_issuer login password '<issuer_password>';
create role db_role_migrations login password '<migrations_password>';

grant connect on database <db_name> to db_role_gateway, db_role_policy, db_role_verifier, db_role_issuer, db_role_migrations;
grant usage on schema public to db_role_gateway, db_role_policy, db_role_verifier, db_role_issuer, db_role_migrations;

-- migrations role: full DDL + DML
grant all privileges on all tables in schema public to db_role_migrations;
grant all privileges on all sequences in schema public to db_role_migrations;
alter default privileges in schema public grant all privileges on tables to db_role_migrations;
alter default privileges in schema public grant all privileges on sequences to db_role_migrations;

-- runtime roles: sequence usage/select where inserts may consume nextval
grant usage, select on all sequences in schema public to db_role_gateway, db_role_policy, db_role_verifier, db_role_issuer;
alter default privileges in schema public grant usage, select on sequences to db_role_gateway, db_role_policy, db_role_verifier, db_role_issuer;

-- gateway role: command/audit events only
grant select, insert, delete on table command_center_audit_events to db_role_gateway;

-- policy role
grant select, insert, update on table policies to db_role_policy;
grant select on table actions to db_role_policy;
grant select, insert, update on table credential_types to db_role_policy;
grant select, insert, update, delete on table verification_challenges to db_role_policy;
grant select, insert, update on table system_metadata to db_role_policy;
grant insert on table audit_logs to db_role_policy;
grant select, insert, update on table anchor_outbox to db_role_policy;
grant select, insert, update on table policy_version_floor to db_role_policy;

-- verifier role
grant select on table policies to db_role_verifier;
grant select, insert, update on table verification_challenges to db_role_verifier;
grant select on table policy_version_floor to db_role_verifier;
grant select on table privacy_tombstones to db_role_verifier;
grant select on table privacy_restrictions to db_role_verifier;
grant select, insert, update on table obligations_executions to db_role_verifier;
grant select, insert on table rate_limit_events to db_role_verifier;
grant insert on table anchor_outbox to db_role_verifier;
grant insert on table obligation_events to db_role_verifier;
grant insert on table capability_signals to db_role_verifier;
grant select, insert, update on table system_metadata to db_role_verifier;

-- issuer role
grant select, insert, update on table issuer_keys to db_role_issuer;
grant select on table credential_types to db_role_issuer;
grant select, insert, update on table status_lists to db_role_issuer;
grant select, insert, update on table status_list_versions to db_role_issuer;
grant select, insert, update on table issuance_events to db_role_issuer;
grant select, insert, update on table anchor_outbox to db_role_issuer;
grant select, insert on table anchor_receipts to db_role_issuer;
grant insert on table audit_logs to db_role_issuer;
grant select, insert, update on table system_metadata to db_role_issuer;
grant select, insert, update on table capability_state to db_role_issuer;
grant select, insert, update, delete on table capability_signals to db_role_issuer;
grant select, insert, update, delete on table capability_issuance_queue to db_role_issuer;
grant select on table capability_rules to db_role_issuer;
grant select, insert, update, delete on table privacy_requests to db_role_issuer;
grant select, insert, update, delete on table privacy_tokens to db_role_issuer;
grant select, insert, update, delete on table privacy_restrictions to db_role_issuer;
grant select, insert, update on table privacy_tombstones to db_role_issuer;
grant select, insert, delete on table rate_limit_events to db_role_issuer;
grant select, insert, delete on table obligation_events to db_role_issuer;
grant select, insert, update, delete on table obligations_executions to db_role_issuer;
