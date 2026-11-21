UPDATE organization.directory_events SET trigger_type = 'manual' WHERE trigger_type = 'scheduled';
ALTER TABLE organization.directory_events
    DROP CONSTRAINT directory_events_trigger_type_check,
    ADD CONSTRAINT directory_events_trigger_type_check CHECK (trigger_type IN ('push', 'manual', 'sign-in'));

ALTER TABLE organization.ldap_connections
    DROP CONSTRAINT ldap_connections_sync_people_check,
    DROP CONSTRAINT ldap_connections_sync_interval_check,
    DROP COLUMN sync_failing,
    DROP COLUMN sync_people,
    DROP COLUMN sync_cursor,
    DROP COLUMN full_sync_at,
    DROP COLUMN sync_succeeded_at,
    DROP COLUMN sync_started_at,
    DROP COLUMN sync_interval_minutes;
