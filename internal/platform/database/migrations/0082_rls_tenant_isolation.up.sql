-- 0082_rls_tenant_isolation
--
-- Defense-in-depth tenant isolation via PostgreSQL Row-Level Security (RLS).
-- This BACKSTOPS — it does not replace — the per-query `WHERE tenant_id = $1`
-- predicates the application already uses.
--
-- Model
-- -----
-- The application runs as a dedicated least-privilege role (`qid_app`) that is
-- NOT the table owner, so RLS applies to it. Migrations run as the owner
-- (DB_MIGRATE_URL), which bypasses RLS with ENABLE-only (no FORCE) so DDL and
-- data backfills keep working. On every connection checkout the pool stamps two
-- session GUCs (see platform/database/postgres/pool.go):
--   * app.tenant_id  — the tenant a {tenantID}-scoped request is bound to
--   * app.bypass_rls — 'on' for account-level/public/worker/seed connections
--     that scope themselves by user id or operate cross-tenant by design
-- The policy below reads those GUCs.
--
-- Activation is OPT-IN: while the app connects as a superuser (e.g. the default
-- local `postgres`), RLS is inert (superusers always bypass). Point DB_URL at
-- the non-superuser `qid_app` role (with DB_MIGRATE_URL at the owner) to
-- enforce. The role is created here WITHOUT login; infra/the deploy runbook
-- grants it LOGIN + a password out of band (no secret in version control).
--
-- NOTE: tables added by future migrations that carry a tenant_id must enable
-- RLS + this policy themselves (or re-run an equivalent block) — this DO block
-- only covers tables present as of 0082.

-- 1. Least-privilege application role (idempotent; login/password added by infra).
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qid_app') THEN
    CREATE ROLE qid_app NOLOGIN;
  END IF;
END $$;

-- 2. Grants: schema usage + table/sequence DML, plus defaults for future objects
--    created by the owner running later migrations.
GRANT USAGE ON SCHEMA public, tenant, "user", auth, rbac, audit, platform TO qid_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA tenant, "user", auth, rbac, audit, platform TO qid_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA tenant, "user", auth, rbac, audit, platform TO qid_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA tenant, "user", auth, rbac, audit, platform GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO qid_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA tenant, "user", auth, rbac, audit, platform GRANT USAGE, SELECT ON SEQUENCES TO qid_app;

-- 3. Enable RLS + a uniform tenant-isolation policy on every table that carries
--    a tenant_id. ENABLE (not FORCE): the owner still bypasses (so migrations
--    work); non-owner roles like qid_app are enforced.
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT table_schema, table_name
    FROM information_schema.columns
    WHERE column_name = 'tenant_id'
      AND table_schema IN ('tenant', 'user', 'auth', 'rbac', 'audit', 'platform')
  LOOP
    EXECUTE format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', r.table_schema, r.table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', r.table_schema, r.table_name);
    EXECUTE format($ddl$
      CREATE POLICY tenant_isolation ON %I.%I
        USING (
          current_setting('app.bypass_rls', true) = 'on'
          OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        )
        WITH CHECK (
          current_setting('app.bypass_rls', true) = 'on'
          OR tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
        )
    $ddl$, r.table_schema, r.table_name);
  END LOOP;
END $$;
