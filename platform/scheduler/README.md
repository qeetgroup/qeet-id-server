# platform/scheduler

Cron-style task scheduler for background maintenance jobs.

Planned: pluggable scheduler (in-process gocron or database-backed) for:
- Session expiry cleanup
- Soft-delete purge (retention policy)
- Audit log integrity verification
- Outbox retry sweep

Current background workers are in `platform/workers/`.
