-- 0147_scheduled_jobs — scheduled maintenance that actually runs, once.
--
-- The maintenance jobs (audit-chain verification and the cleanups) ran only in
-- a separate scheduler binary that nothing shipped or started, each instance
-- on its own ticker, and a verification left nothing but a log line. Now any
-- instance may run them: before running a job it claims it here, and only a
-- claim older than the job's interval can be taken, so each job runs once per
-- interval however many instances run the scheduler.
CREATE TABLE platform.scheduled_job_runs (
    job               TEXT PRIMARY KEY,
    last_started_at   TIMESTAMPTZ NOT NULL,
    last_finished_at  TIMESTAMPTZ,
    last_succeeded_at TIMESTAMPTZ,
    last_error        TEXT
);

-- Every scheduled verification of the audit chains, kept as evidence: when it
-- ran, what it walked, and the first broken link if any.
CREATE TABLE platform.audit_verification_runs (
    id                UUID PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ NOT NULL,
    scope             TEXT NOT NULL DEFAULT 'all',
    tenants_walked    INTEGER NOT NULL,
    rows_checked      BIGINT NOT NULL,
    outcome           TEXT NOT NULL CHECK (outcome IN ('intact', 'broken', 'error')),
    broken_tenant_id  UUID,
    first_broken_link UUID,
    broken_reason     TEXT,
    error             TEXT
);
CREATE INDEX audit_verification_runs_started_idx ON platform.audit_verification_runs (started_at DESC);
