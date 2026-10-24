-- 0163_audit_sign_in_index — the sign-ins of an organisation, by time.
--
-- The dashboard counts sign-ins and the people who made them from the sign-in
-- log, the auth.login_succeeded audit events, over up to 60 days.
-- idx_audit_tenant_time finds an organisation's window but every action in it,
-- read from the table; this index holds the sign-ins alone, with the person, so
-- counting people reads the index only.
CREATE INDEX idx_audit_sign_ins
    ON audit.events (tenant_id, created_at)
    INCLUDE (actor_user_id)
    WHERE action = 'auth.login_succeeded';
