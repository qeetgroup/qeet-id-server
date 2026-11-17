-- 0001_schemas_and_role — the seven schemas and the role the application runs as.
--
-- The application's connections run as qeet_app, which holds every privilege on
-- what the migrations create in these schemas: the default privileges below
-- grant them as each table and function is made. Row-level security (0011)
-- applies to qeet_app because it owns nothing.

-- What the platform itself keeps, for no one organisation: signing keys,
-- jobs, the outbox, billing plans, audit checkpoints.
CREATE SCHEMA platform;

-- Accounts: the people who sign in, and what belongs to a person across
-- organisations.
CREATE SCHEMA account;

-- Organisations and what each one configures: connections, groups, policies,
-- secrets, billing.
CREATE SCHEMA tenant;

-- Roles, permissions and who holds which role in which organisation.
CREATE SCHEMA rbac;

-- Sign-in: sessions, credentials, second factors, applications, tokens and
-- codes.
CREATE SCHEMA auth;

-- The audit trail and what is derived from it.
CREATE SCHEMA audit;

-- Qeet AI: provider settings, conversations and usage.
CREATE SCHEMA qeetai;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qeet_app') THEN
        CREATE ROLE qeet_app NOLOGIN;
    END IF;
END
$$;
GRANT qeet_app TO CURRENT_USER;

GRANT USAGE ON SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant TO qeet_app;
GRANT ALL ON ALL TABLES IN SCHEMA public TO qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant
    GRANT ALL ON TABLES TO qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant
    GRANT ALL ON SEQUENCES TO qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant
    GRANT EXECUTE ON FUNCTIONS TO qeet_app;
