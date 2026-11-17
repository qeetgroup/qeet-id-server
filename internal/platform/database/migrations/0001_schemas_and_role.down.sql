ALTER DEFAULT PRIVILEGES IN SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant
    REVOKE EXECUTE ON FUNCTIONS FROM qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant
    REVOKE ALL ON SEQUENCES FROM qeet_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant
    REVOKE ALL ON TABLES FROM qeet_app;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM qeet_app;
REVOKE USAGE ON SCHEMA account, audit, auth, platform, public, qeetai, rbac, tenant FROM qeet_app;
DROP SCHEMA IF EXISTS qeetai;
DROP SCHEMA IF EXISTS audit;
DROP SCHEMA IF EXISTS auth;
DROP SCHEMA IF EXISTS rbac;
DROP SCHEMA IF EXISTS tenant;
DROP SCHEMA IF EXISTS account;
DROP SCHEMA IF EXISTS platform;
-- The role stays: it belongs to the server, and other databases on it may use it.
