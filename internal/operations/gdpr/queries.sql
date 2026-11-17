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
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, tenant_id, framework, generated_at, generated_by,
       pass_count, fail_count, na_count
FROM tenant.compliance_evidence_runs
WHERE tenant_id = @tenant_id AND framework = @framework
ORDER BY generated_at DESC
LIMIT 1001;

-- name: GetEvidenceRun :one
-- Fetch a single evidence run with its full controls JSONB blob.
SELECT id, tenant_id, framework, generated_at, generated_by,
       pass_count, fail_count, na_count, controls
FROM tenant.compliance_evidence_runs
WHERE id = @id AND tenant_id = @tenant_id;

-- -----------------------------------------------------------------------
-- Control check queries — each check function has one query here.
-- -----------------------------------------------------------------------

-- name: CheckMFAEnforcement :one
SELECT mfa_enforcement, mfa_grace_days, mfa_enforced_since
FROM tenant.security_policies WHERE tenant_id = @tenant_id;

-- CountUsersWithoutSecondFactor counts the tenant's accounts holding no
-- factor a sign-in challenge can be met with (as auth.LoginFactors reads
-- them): they set one up at their next sign-in.
-- name: CountUsersWithoutSecondFactor :one
SELECT count(*)::int
FROM account.users u
WHERE u.tenant_id = @tenant_id AND u.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_recovery_codes r WHERE r.user_id = u.id AND r.used_at IS NULL)
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_otp_factors f WHERE f.user_id = u.id AND f.verified_at IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = u.id)
  AND NOT (
      COALESCE((SELECT ap.passkey_enabled FROM tenant.auth_policy ap WHERE ap.tenant_id = u.tenant_id), TRUE)
      AND EXISTS (SELECT 1 FROM auth.passkey_credentials p WHERE p.user_id = u.id)
  );

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

-- CheckLogSinksCount counts the enabled log sinks, and of those the ones
-- delivering: forwarded within a day and not failing now.
-- name: CheckLogSinksCount :one
SELECT count(*) AS enabled,
       count(*) FILTER (WHERE last_error = '' AND last_forwarded_at > NOW() - INTERVAL '1 day') AS delivering
FROM tenant.log_sinks WHERE tenant_id = @tenant_id AND enabled;

-- name: CheckPurgeRequestCount :one
SELECT count(*) FROM account.purge_requests WHERE tenant_id = @tenant_id;

-- name: CheckExportRequestCount :one
SELECT count(*) FROM account.export_requests WHERE tenant_id = @tenant_id;

-- -----------------------------------------------------------------------
-- GDPR purge requests
-- -----------------------------------------------------------------------

-- name: InsertPurgeRequest :one
-- Queue a right-to-erasure request. grace_until is pre-computed in Go
-- (time.Now().UTC().Add(s.grace)) to avoid pgtype.Interval parameter type issues.
-- subject_id keeps the account's ID once the account itself is deleted, and
-- subject_email and subject_name who it was filed for until they are erased.
INSERT INTO account.purge_requests (tenant_id, user_id, subject_id, requested_by, reason, grace_until,
                                   subject_email, subject_name)
SELECT @tenant_id, @subject_id::uuid, @subject_id::uuid, @requested_by, @reason, @grace_until, u.email, u.display_name
FROM account.users u WHERE u.id = @subject_id::uuid AND u.tenant_id = @tenant_id
RETURNING id, tenant_id, subject_id, requested_by, reason, status,
          grace_until, completed_at, created_at, subject_email, subject_name;

-- name: CancelPurgeRequest :one
-- Cancel a pending purge request (e.g. the subject changed their mind),
-- returning its user. No row when it is already completed or not found.
UPDATE account.purge_requests
SET status = 'cancelled'
WHERE id = @id AND tenant_id = @tenant_id AND status = 'pending'
RETURNING subject_id;

-- name: ListPurgeRequests :many
-- List all purge requests for a tenant, most recent first.
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, tenant_id, subject_id, requested_by, reason, status,
       grace_until, completed_at, created_at, subject_email, subject_name
FROM account.purge_requests
WHERE tenant_id = @tenant_id
ORDER BY created_at DESC
LIMIT 1001;

-- name: PurgeUserPII :one
-- Replace PII fields with redacted markers and soft-delete the user row,
-- returning the address it had. Audit references are intentionally preserved;
-- only personal data is erased.
UPDATE account.users u
SET email              = 'redacted-' || u.id::text || '@gdpr.invalid',
    phone              = NULL,
    display_name       = NULL,
    avatar_url         = NULL,
    external_id        = NULL,
    metadata           = '{}'::jsonb,
    email_verified_at  = NULL,
    phone_verified_at  = NULL,
    status             = 'deleted',
    deleted_at         = COALESCE(u.deleted_at, NOW()),
    updated_at         = NOW()
FROM (SELECT p.id, p.email FROM account.users p WHERE p.id = @user_id FOR UPDATE) prior
WHERE u.id = prior.id
RETURNING prior.email;

-- name: RevokeUserSessions :exec
UPDATE auth.sessions
SET revoked_at = COALESCE(revoked_at, NOW())
WHERE user_id = @user_id;

-- name: CompletePurgeRequest :exec
UPDATE account.purge_requests
SET status = 'completed', completed_at = NOW(), subject_email = NULL, subject_name = NULL
WHERE id = @id;

-- -----------------------------------------------------------------------
-- GDPR export requests
-- -----------------------------------------------------------------------

-- name: InsertExportRequest :one
-- subject_id keeps the account's ID once the account itself is deleted.
INSERT INTO account.export_requests (tenant_id, user_id, subject_id, requested_by)
VALUES (@tenant_id, @subject_id::uuid, @subject_id::uuid, @requested_by)
RETURNING id, tenant_id, subject_id, requested_by, status, completed_at, created_at;

-- name: ListExportRequests :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, tenant_id, subject_id, requested_by, status, error, completed_at, created_at
FROM account.export_requests
WHERE tenant_id = @tenant_id
ORDER BY created_at DESC
LIMIT 1001;

-- name: GetExportRequest :one
SELECT id, tenant_id, subject_id, requested_by, status, payload, error,
       completed_at, created_at
FROM account.export_requests
WHERE id = @id AND tenant_id = @tenant_id;

-- name: FailExportRequest :execrows
-- Mark an export request the worker holds the lease on as failed.
UPDATE account.export_requests
SET status = 'failed', error = @error_msg, completed_at = NOW(),
    lease_owner = NULL, lease_until = NULL
WHERE id = @id AND tenant_id = @tenant_id AND lease_owner = @lease_owner;

-- name: ReadyExportRequest :exec
UPDATE account.export_requests
SET status = 'ready', payload = @payload, completed_at = NOW()
WHERE id = @id;

-- ExpireReadyExports deletes the payloads of at most @max_rows exports that
-- became ready before @cutoff, or whose account has been deleted, and marks
-- them expired.
-- name: ExpireReadyExports :execrows
UPDATE account.export_requests SET payload = NULL, status = 'expired'
WHERE ctid = ANY(ARRAY(
    SELECT r.ctid FROM account.export_requests r
    WHERE r.status = 'ready' AND (r.completed_at < @cutoff::timestamptz OR r.user_id IS NULL)
    LIMIT @max_rows));

-- -----------------------------------------------------------------------
-- User data collection for export (collectUserData)
-- -----------------------------------------------------------------------

-- name: GetUserProfileForExport :one
SELECT email, phone, display_name, avatar_url, status, metadata,
       email_verified_at, phone_verified_at, created_at
FROM account.users
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

-- -----------------------------------------------------------------------
-- Export sections: one organisation's part of the person's data when
-- tenant_id is set (its export of a member), all of it when it is null (the
-- person's own export).
-- -----------------------------------------------------------------------

-- ListUserIdentitiesForExport lists the accounts linked for signing in: social
-- and single sign-on identities, and the platform's own social sign-ins.
-- name: ListUserIdentitiesForExport :many
SELECT i.provider, i.subject, i.email, i.linked_at
FROM account.external_identities i
WHERE i.user_id = @user_id AND (sqlc.narg('tenant_id')::uuid IS NULL OR i.tenant_id = sqlc.narg('tenant_id'))
UNION ALL
SELECT p.provider, p.subject, p.email, p.linked_at
FROM auth.platform_social_identities p
WHERE p.user_id = @user_id
ORDER BY linked_at;

-- name: ListUserOTPFactorsForExport :many
SELECT channel, destination, verified_at, created_at
FROM auth.mfa_otp_factors
WHERE user_id = @user_id
ORDER BY created_at;

-- ListUserConsentsForExport lists the applications the person consented to
-- and the scopes they granted.
-- name: ListUserConsentsForExport :many
SELECT c.client_id, COALESCE(cl.name, '')::text AS client_name, c.scopes, c.granted_at
FROM auth.oidc_consents c
LEFT JOIN auth.oidc_clients cl ON cl.client_id = c.client_id
WHERE c.user_id = @user_id AND (sqlc.narg('tenant_id')::uuid IS NULL OR cl.tenant_id = sqlc.narg('tenant_id'))
ORDER BY c.granted_at;

-- ListUserGrantsForExport lists the person's live application grants, by
-- their latest refresh token.
-- name: ListUserGrantsForExport :many
SELECT t.client_id, COALESCE(cl.name, '')::text AS client_name, t.scopes, t.issued_at, t.expires_at
FROM auth.oidc_refresh_tokens t
LEFT JOIN auth.oidc_clients cl ON cl.client_id = t.client_id
WHERE t.user_id = @user_id AND t.revoked_at IS NULL AND t.replaced_by IS NULL AND t.expires_at > NOW()
  AND (sqlc.narg('tenant_id')::uuid IS NULL OR t.tenant_id = sqlc.narg('tenant_id'))
ORDER BY t.issued_at;

-- name: ListUserGroupsForExport :many
SELECT g.name, o.name AS organization, m.added_at
FROM tenant.group_members m
JOIN tenant.groups g ON g.id = m.group_id AND g.tenant_id = m.tenant_id
JOIN tenant.tenants o ON o.id = m.tenant_id
WHERE m.user_id = @user_id AND (sqlc.narg('tenant_id')::uuid IS NULL OR m.tenant_id = sqlc.narg('tenant_id'))
ORDER BY m.added_at;

-- ListUserSignInsForExport lists the person's most recent sign-ins, made and
-- failed, from the audit trail.
-- name: ListUserSignInsForExport :many
SELECT e.created_at, (e.action = 'auth.login_succeeded')::boolean AS succeeded,
       COALESCE(e.metadata->>'method', '')::text AS method,
       COALESCE(host(e.ip), '')::text AS ip, COALESCE(e.user_agent, '')::text AS user_agent,
       COALESCE(o.name, '')::text AS organization
FROM audit.events e
LEFT JOIN tenant.tenants o ON o.id = e.tenant_id
WHERE e.actor_user_id = @user_id::uuid AND e.action IN ('auth.login_succeeded', 'auth.sign_in_failed')
  AND (sqlc.narg('tenant_id')::uuid IS NULL OR e.tenant_id = sqlc.narg('tenant_id'))
ORDER BY e.created_at DESC
LIMIT 1000;

-- -----------------------------------------------------------------------
-- Compliance controls: owners, the last run, external audits
-- -----------------------------------------------------------------------

-- name: LatestEvidenceControls :one
-- The control results of the tenant's latest run of a framework.
SELECT controls, generated_at FROM tenant.compliance_evidence_runs
WHERE tenant_id = @tenant_id AND framework = @framework
ORDER BY generated_at DESC LIMIT 1;

-- name: ListControlOwners :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT o.control_id, o.user_id, u.email, u.display_name, o.updated_at
FROM tenant.compliance_control_owners o
LEFT JOIN account.users u ON u.id = o.user_id
WHERE o.tenant_id = @tenant_id
ORDER BY o.control_id
LIMIT 1001;

-- name: UpsertControlOwner :exec
INSERT INTO tenant.compliance_control_owners (tenant_id, control_id, user_id, updated_by, updated_at)
VALUES (@tenant_id, @control_id, @user_id, sqlc.narg('updated_by'), NOW())
ON CONFLICT (tenant_id, control_id) DO UPDATE SET
    user_id = EXCLUDED.user_id, updated_by = EXCLUDED.updated_by, updated_at = NOW();

-- name: DeleteControlOwner :execrows
DELETE FROM tenant.compliance_control_owners WHERE tenant_id = @tenant_id AND control_id = @control_id;

-- name: IsTenantMember :one
-- Whether the user is one of the tenant's people: its own, or holding a role
-- there.
SELECT EXISTS (
    SELECT 1 FROM account.users u WHERE u.id = @user_id AND u.deleted_at IS NULL
      AND (u.tenant_id = @tenant_id OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.tenant_id = @tenant_id))
);

-- name: ListComplianceAudits :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, framework, kind, body, scope, reference, issued_on, expires_on, created_by, created_at
FROM tenant.compliance_audits
WHERE tenant_id = @tenant_id AND (sqlc.narg('framework')::text IS NULL OR framework = sqlc.narg('framework'))
ORDER BY issued_on DESC, created_at DESC
LIMIT 1001;

-- name: InsertComplianceAudit :one
INSERT INTO tenant.compliance_audits (tenant_id, framework, kind, body, scope, reference, issued_on, expires_on, created_by)
VALUES (@tenant_id, @framework, @kind, @body, @scope, @reference, @issued_on, sqlc.narg('expires_on'), sqlc.narg('created_by'))
RETURNING id, framework, kind, body, scope, reference, issued_on, expires_on, created_by, created_at;

-- name: DeleteComplianceAudit :one
DELETE FROM tenant.compliance_audits WHERE id = @id AND tenant_id = @tenant_id
RETURNING framework, kind, body;
