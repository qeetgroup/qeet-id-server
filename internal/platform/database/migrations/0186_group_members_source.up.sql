-- 0186_group_members_source — finds the memberships a connection's sign-ins made.
CREATE INDEX CONCURRENTLY group_members_source
    ON tenant.group_members (source_connection_id, user_id) WHERE source_connection_id IS NOT NULL;
