-- Queries for the compliance domain (evidence.go + gdpr.go).
-- All queries are static.
--
-- CreatePurgeRequest uses @grace_until (a pre-computed timestamptz from Go)
-- instead of NOW() + $5::interval to avoid the text→interval cast, whose
-- generated parameter type is ambiguous between text and pgtype.Interval.
-- The value is identical: time.Now().UTC().Add(s.grace).

-- -----------------------------------------------------------------------
-- Evidence runs (SOC 2 / ISO 27001)
-- -----------------------------------------------------------------------

-- name: InsertEvidenceRun :one
-- Persist one compliance-check snapshot; controls are stored as JSONB so
-- the full report is retrievable without a JOIN.
INSERT INTO tenant.compliance_evidence_runs
    (tenant_id, framework, generated_by, pass_count, fail_count, na_count, controls)
VALUES (@tenant_id, @framework, @generated_by, @pass_count, @fail_count, @na_count, @controls)
RETURNING id, tenant_id, framework, generated_at, generated_by,
          pass_count, fail_count, na_count;

-- name: ListEvidenceRuns :many
-- List previous runs for a tenant+framework, most recent first.
-- Controls are excluded from the list response (use GetEvidenceRun for full report).
SELECT id, tenant_id, framework, generated_at, generated_by,
       pass_count, fail_count, na_count
FROM tenant.compliance_evidence_runs
WHERE tenant_id = @tenant_id AND framework = @framework
ORDER BY generated_at DESC
LIMIT 100;

-- name: GetEvidenceRun :one
-- Fetch a single evidence run with its full controls JSONB blob.
SELECT id, tenant_id, framework, generated_at, generated_by,
       pass_count, fail_count, na_count, controls
FROM tenant.compliance_evidence_runs
WHERE id = @id AND tenant_id = @tenant_id;

-- name: CountEvidenceRuns :one
-- Count total evidence runs for a tenant (used in tests to verify persistence).
SELECT count(*) FROM tenant.compliance_evidence_runs WHERE tenant_id = @tenant_id;

-- -----------------------------------------------------------------------
-- Control check queries — each check function has one query here.
-- -----------------------------------------------------------------------

-- name: CheckMFAEnforcement :one
SELECT mfa_enforcement FROM tenant.security_policies WHERE tenant_id = @tenant_id;

-- name: CheckPasswordMinLength :one
SELECT password_min_length FROM tenant.auth_policy WHERE tenant_id = @tenant_id;

-- name: CheckPasswordComplexity :one
SELECT password_require_uppercase, password_require_number, password_require_symbol
FROM tenant.auth_policy WHERE tenant_id = @tenant_id;

-- name: CheckSessionTimeout :one
SELECT extract(epoch FROM session_max_age)::float8 AS session_seconds
FROM tenant.security_policies WHERE tenant_id = @tenant_id;

-- name: CheckRiskSettings :one
SELECT medium_threshold, high_threshold
FROM auth.risk_settings WHERE tenant_id = @tenant_id;

-- name: CheckRBACRoles :one
SELECT count(*) FROM rbac.roles WHERE tenant_id = @tenant_id;

-- name: CheckRBACAssignments :one
SELECT count(*) FROM rbac.user_roles WHERE tenant_id = @tenant_id;

-- name: CheckRetentionPolicy :one
SELECT deleted_users_enabled, deleted_users_days
FROM tenant.retention_policy WHERE tenant_id = @tenant_id;

-- name: CheckIPRulesConfig :one
SELECT enabled FROM tenant.ip_rules_config WHERE tenant_id = @tenant_id;

-- name: CheckIPRulesCount :one
SELECT count(*) FROM tenant.ip_rules WHERE tenant_id = @tenant_id;

-- name: CheckSecretsCount :one
SELECT count(*) FROM tenant.secrets WHERE tenant_id = @tenant_id;

-- name: CheckAuditEventCount :one
SELECT count(*) FROM audit.events
WHERE tenant_id = @tenant_id AND created_at >= now() - interval '30 days';

-- name: CheckLogSinksCount :one
SELECT count(*) FROM tenant.log_sinks WHERE tenant_id = @tenant_id AND enabled;

-- name: CheckWebhookSubscriptionsCount :one
SELECT count(*) FROM tenant.webhook_subscriptions
WHERE tenant_id = @tenant_id AND disabled_at IS NULL;

-- name: CheckPurgeRequestCount :one
SELECT count(*) FROM "user".purge_requests WHERE tenant_id = @tenant_id;

-- name: CheckExportRequestCount :one
SELECT count(*) FROM "user".export_requests WHERE tenant_id = @tenant_id;

-- -----------------------------------------------------------------------
-- GDPR purge requests
-- -----------------------------------------------------------------------

-- name: InsertPurgeRequest :one
-- Queue a right-to-erasure request. grace_until is pre-computed in Go
-- (time.Now().UTC().Add(s.grace)) to avoid pgtype.Interval parameter type issues.
INSERT INTO "user".purge_requests (tenant_id, user_id, requested_by, reason, grace_until)
VALUES (@tenant_id, @user_id, @requested_by, @reason, @grace_until)
RETURNING id, tenant_id, user_id, requested_by, reason, status,
          grace_until, completed_at, created_at;

-- name: CancelPurgeRequest :execrows
-- Cancel a pending purge request (e.g. the subject changed their mind).
-- Returns 0 rows affected when the request is already completed or not found.
UPDATE "user".purge_requests
SET status = 'cancelled'
WHERE id = @id AND status = 'pending';

-- name: ListPurgeRequests :many
-- List all purge requests for a tenant, most recent first.
SELECT id, tenant_id, user_id, requested_by, reason, status,
       grace_until, completed_at, created_at
FROM "user".purge_requests
WHERE tenant_id = @tenant_id
ORDER BY created_at DESC
LIMIT 200;

-- name: GetPendingPurgeRequests :many
-- Pick a batch of ripe purge requests for the background sweep.
-- FOR UPDATE SKIP LOCKED prevents concurrent sweepers from double-processing.
SELECT id, user_id
FROM "user".purge_requests
WHERE status = 'pending' AND grace_until <= NOW()
LIMIT 50
FOR UPDATE SKIP LOCKED;

-- name: PurgeUserPII :exec
-- Replace PII fields with redacted markers and soft-delete the user row.
-- Audit references are intentionally preserved; only personal data is erased.
UPDATE "user".users
SET email              = 'redacted-' || id::text || '@gdpr.invalid',
    phone              = NULL,
    display_name       = NULL,
    metadata           = '{}'::jsonb,
    email_verified_at  = NULL,
    phone_verified_at  = NULL,
    status             = 'deleted',
    deleted_at         = COALESCE(deleted_at, NOW()),
    updated_at         = NOW()
WHERE id = @user_id;

-- name: DeletePasswordCredentials :exec
DELETE FROM auth.password_credentials WHERE user_id = @user_id;

-- name: DeleteMFATOTP :exec
DELETE FROM auth.mfa_totp WHERE user_id = @user_id;

-- name: DeleteMFARecoveryCodes :exec
DELETE FROM auth.mfa_recovery_codes WHERE user_id = @user_id;

-- name: RevokeUserSessions :exec
UPDATE auth.sessions
SET revoked_at = COALESCE(revoked_at, NOW())
WHERE user_id = @user_id;

-- name: CompletePurgeRequest :exec
UPDATE "user".purge_requests
SET status = 'completed', completed_at = NOW()
WHERE id = @id;

-- -----------------------------------------------------------------------
-- GDPR export requests
-- -----------------------------------------------------------------------

-- name: InsertExportRequest :one
INSERT INTO "user".export_requests (tenant_id, user_id, requested_by)
VALUES (@tenant_id, @user_id, @requested_by)
RETURNING id, tenant_id, user_id, requested_by, status, completed_at, created_at;

-- name: ListExportRequests :many
SELECT id, tenant_id, user_id, requested_by, status, error, completed_at, created_at
FROM "user".export_requests
WHERE tenant_id = @tenant_id
ORDER BY created_at DESC
LIMIT 200;

-- name: GetExportRequest :one
SELECT id, tenant_id, user_id, requested_by, status, payload, error,
       completed_at, created_at
FROM "user".export_requests
WHERE id = @id AND tenant_id = @tenant_id;

-- name: GetPendingExportRequests :many
-- Pick a batch of pending export jobs for the background sweep.
SELECT id, tenant_id, user_id
FROM "user".export_requests
WHERE status = 'pending'
LIMIT 20
FOR UPDATE SKIP LOCKED;

-- name: FailExportRequest :exec
UPDATE "user".export_requests
SET status = 'failed', error = @error_msg, completed_at = NOW()
WHERE id = @id;

-- name: ReadyExportRequest :exec
UPDATE "user".export_requests
SET status = 'ready', payload = @payload, completed_at = NOW()
WHERE id = @id;

-- -----------------------------------------------------------------------
-- User data collection for export (collectUserData)
-- -----------------------------------------------------------------------

-- name: GetUserProfileForExport :one
SELECT email, phone, display_name, status,
       email_verified_at, phone_verified_at, created_at
FROM "user".users
WHERE id = @user_id AND tenant_id = @tenant_id;

-- name: ListUserSessionsForExport :many
-- COALESCE ensures a non-null result for ip (inet is nullable; host() of NULL = NULL).
SELECT id, COALESCE(host(ip), '') AS ip, user_agent, created_at, last_seen_at, revoked_at
FROM auth.sessions
WHERE user_id = @user_id AND tenant_id = @tenant_id
ORDER BY created_at DESC;

-- name: ListUserPasskeysForExport :many
SELECT id, name, transports, created_at, last_used_at
FROM auth.passkey_credentials
WHERE user_id = @user_id;

-- name: ListUserRolesForExport :many
SELECT r.name AS role_name, ur.granted_at
FROM rbac.user_roles ur
JOIN rbac.roles r ON r.id = ur.role_id
WHERE ur.user_id = @user_id AND ur.tenant_id = @tenant_id;

-- name: GetUserMFAStatus :one
-- Return whether the user has a confirmed TOTP factor.
-- Explicit ::boolean cast ensures sqlc infers bool rather than interface{}.
SELECT (confirmed_at IS NOT NULL)::boolean AS mfa_enabled
FROM auth.mfa_totp
WHERE user_id = @user_id;
