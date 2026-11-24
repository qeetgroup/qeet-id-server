-- 0013_ldap_sync — the scheduled sync of LDAP connections (internal/federation/ldap/sync.go).
-- sync_started_at is the run's claim, so two instances never sync one connection at once.

ALTER TABLE organization.ldap_connections
    ADD COLUMN sync_interval_minutes INTEGER NOT NULL DEFAULT 15,
    ADD COLUMN sync_started_at TIMESTAMPTZ,
    ADD COLUMN sync_succeeded_at TIMESTAMPTZ,
    ADD COLUMN full_sync_at TIMESTAMPTZ,
    ADD COLUMN sync_cursor TEXT,
    ADD COLUMN sync_people INTEGER,
    ADD COLUMN sync_failing BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT ldap_connections_sync_interval_check CHECK (sync_interval_minutes BETWEEN 5 AND 60),
    ADD CONSTRAINT ldap_connections_sync_people_check CHECK (sync_people >= 0);

ALTER TABLE organization.directory_events
    DROP CONSTRAINT directory_events_trigger_type_check,
    ADD CONSTRAINT directory_events_trigger_type_check
        CHECK (trigger_type IN ('push', 'manual', 'sign-in', 'scheduled')) NOT VALID;
ALTER TABLE organization.directory_events VALIDATE CONSTRAINT directory_events_trigger_type_check;
