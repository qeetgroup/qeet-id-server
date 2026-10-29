-- 0175_log_sink_lease — one instance forwards a log sink at a time, and a
-- failing sink backs off.
--
-- Every instance forwarded every sink, sending each event several times and
-- racing on the cursor, and a failing sink was retried every ten seconds for
-- ever. An instance now leases a sink while it forwards it, and a sink that
-- fails waits longer after each failure before the next attempt.
ALTER TABLE tenant.log_sinks
    ADD COLUMN leased_until   TIMESTAMPTZ,
    ADD COLUMN failures       INTEGER NOT NULL DEFAULT 0 CHECK (failures >= 0),
    ADD COLUMN next_attempt_at TIMESTAMPTZ;
