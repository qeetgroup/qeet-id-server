-- Reverse 0082_rls_tenant_isolation: drop the tenant-isolation policies, disable
-- RLS, revoke the app role's grants, and drop the role. (Stop the app first —
-- DROP ROLE fails while qid_app has live connections.)

DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT table_schema, table_name
    FROM information_schema.columns
    WHERE column_name = 'tenant_id'
      AND table_schema IN ('tenant', 'user', 'auth', 'rbac', 'audit', 'platform')
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.%I', r.table_schema, r.table_name);
    EXECUTE format('ALTER TABLE %I.%I DISABLE ROW LEVEL SECURITY', r.table_schema, r.table_name);
  END LOOP;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qid_app') THEN
    ALTER DEFAULT PRIVILEGES IN SCHEMA tenant, "user", auth, rbac, audit, platform REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM qid_app;
    ALTER DEFAULT PRIVILEGES IN SCHEMA tenant, "user", auth, rbac, audit, platform REVOKE USAGE, SELECT ON SEQUENCES FROM qid_app;
    EXECUTE 'REVOKE ALL ON ALL TABLES IN SCHEMA tenant, "user", auth, rbac, audit, platform FROM qid_app';
    EXECUTE 'REVOKE ALL ON ALL SEQUENCES IN SCHEMA tenant, "user", auth, rbac, audit, platform FROM qid_app';
    EXECUTE 'REVOKE USAGE ON SCHEMA public, tenant, "user", auth, rbac, audit, platform FROM qid_app';
    DROP ROLE IF EXISTS qid_app;
  END IF;
END $$;
