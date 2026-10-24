-- 0161_user_roles_by_tenant — find an organisation's members without reading
-- every organisation's.
--
-- The member list, its counts and every "who holds a role here" check filter
-- rbac.user_roles by tenant, but both of its indexes lead with user_id, so each
-- read scanned the whole table: one organisation's page cost as much as the
-- platform's user count.
CREATE INDEX idx_user_roles_tenant ON rbac.user_roles (tenant_id, user_id);
