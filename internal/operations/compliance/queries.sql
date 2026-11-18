-- Queries for the compliance domain: SOC 2 and ISO 27001 evidence runs, the
-- control checks they make, control owners and external audits.
-- All queries are static.

-- -----------------------------------------------------------------------
-- Evidence runs (SOC 2 / ISO 27001)
-- -----------------------------------------------------------------------

-- name: InsertEvidenceRun :one
-- Persist one compliance-check snapshot; controls are stored as JSONB so
-- the full report is retrievable without a JOIN.
INSERT INTO organization.compliance_evidence_runs
    (organization_id, framework, generated_by, pass_count, fail_count, na_count, controls)
VALUES (@organization_id, @framework, @generated_by, @pass_count, @fail_count, @na_count, @controls)
RETURNING id, organization_id, framework, generated_at, generated_by,
          pass_count, fail_count, na_count;

-- name: ListEvidenceRuns :many
-- List previous runs for an organization+framework, most recent first.
-- Controls are excluded from the list response (use GetEvidenceRun for full report).
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, framework, generated_at, generated_by,
       pass_count, fail_count, na_count
FROM organization.compliance_evidence_runs
WHERE organization_id = @organization_id AND framework = @framework
ORDER BY generated_at DESC
LIMIT 1001;

-- name: GetEvidenceRun :one
-- Fetch a single evidence run with its full controls JSONB blob.
SELECT id, organization_id, framework, generated_at, generated_by,
       pass_count, fail_count, na_count, controls
FROM organization.compliance_evidence_runs
WHERE id = @id AND organization_id = @organization_id;

-- -----------------------------------------------------------------------
-- Control check queries — each check function has one query here.
-- -----------------------------------------------------------------------

-- name: CheckMFAEnforcement :one
SELECT mfa_enforcement, mfa_grace_days, mfa_enforced_since
FROM organization.security_policies WHERE organization_id = @organization_id;

-- CountUsersWithoutSecondFactor counts the organization's accounts holding no
-- factor a sign-in challenge can be met with (as auth.LoginFactors reads
-- them): they set one up at their next sign-in.
-- name: CountUsersWithoutSecondFactor :one
SELECT count(*)::int
FROM account.users u
WHERE u.organization_id = @organization_id AND u.deleted_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = u.id AND t.confirmed_at IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_recovery_codes r WHERE r.user_id = u.id AND r.used_at IS NULL)
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_otp_factors f WHERE f.user_id = u.id AND f.verified_at IS NOT NULL)
  AND NOT EXISTS (SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = u.id)
  AND NOT (
      COALESCE((SELECT ap.passkey_enabled FROM organization.auth_policy ap WHERE ap.organization_id = u.organization_id), TRUE)
      AND EXISTS (SELECT 1 FROM auth.passkey_credentials p WHERE p.user_id = u.id)
  );

-- name: CheckPasswordMinLength :one
SELECT password_min_length FROM organization.auth_policy WHERE organization_id = @organization_id;

-- name: CheckPasswordComplexity :one
SELECT password_require_uppercase, password_require_number, password_require_symbol
FROM organization.auth_policy WHERE organization_id = @organization_id;

-- name: CheckSessionTimeout :one
SELECT extract(epoch FROM session_max_age)::float8 AS session_seconds
FROM organization.security_policies WHERE organization_id = @organization_id;

-- name: CheckRiskSettings :one
SELECT medium_threshold, high_threshold
FROM auth.risk_settings WHERE organization_id = @organization_id;

-- name: CheckRBACRoles :one
SELECT count(*) FROM rbac.roles WHERE organization_id = @organization_id;

-- name: CheckRBACAssignments :one
SELECT count(*) FROM rbac.user_roles WHERE organization_id = @organization_id;

-- name: CheckRetentionPolicy :one
SELECT deleted_users_enabled, deleted_users_days
FROM organization.retention_policy WHERE organization_id = @organization_id;

-- name: CheckIPRulesConfig :one
SELECT enabled FROM organization.ip_rules_config WHERE organization_id = @organization_id;

-- name: CheckIPRulesCount :one
SELECT count(*) FROM organization.ip_rules WHERE organization_id = @organization_id;

-- name: CheckSecretsCount :one
SELECT count(*) FROM organization.secrets WHERE organization_id = @organization_id;

-- name: CheckAuditEventCount :one
SELECT count(*) FROM audit.events
WHERE organization_id = @organization_id AND created_at >= now() - interval '30 days';

-- CheckLogSinksCount counts the enabled log sinks, and of those the ones
-- delivering: forwarded within a day and not failing now.
-- name: CheckLogSinksCount :one
SELECT count(*) AS enabled,
       count(*) FILTER (WHERE last_error = '' AND last_forwarded_at > NOW() - INTERVAL '1 day') AS delivering
FROM organization.log_sinks WHERE organization_id = @organization_id AND enabled;

-- name: CheckPurgeRequestCount :one
SELECT count(*) FROM account.purge_requests WHERE organization_id = @organization_id;

-- name: CheckExportRequestCount :one
SELECT count(*) FROM account.export_requests WHERE organization_id = @organization_id;

-- -----------------------------------------------------------------------
-- Compliance controls: owners, the last run, external audits
-- -----------------------------------------------------------------------

-- name: LatestEvidenceControls :one
-- The control results of the organization's latest run of a framework.
SELECT controls, generated_at FROM organization.compliance_evidence_runs
WHERE organization_id = @organization_id AND framework = @framework
ORDER BY generated_at DESC LIMIT 1;

-- name: ListControlOwners :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT o.control_id, o.user_id, u.email, u.display_name, o.updated_at
FROM organization.compliance_control_owners o
LEFT JOIN account.users u ON u.id = o.user_id
WHERE o.organization_id = @organization_id
ORDER BY o.control_id
LIMIT 1001;

-- name: UpsertControlOwner :exec
INSERT INTO organization.compliance_control_owners (organization_id, control_id, user_id, updated_by, updated_at)
VALUES (@organization_id, @control_id, @user_id, sqlc.narg('updated_by'), NOW())
ON CONFLICT (organization_id, control_id) DO UPDATE SET
    user_id = EXCLUDED.user_id, updated_by = EXCLUDED.updated_by, updated_at = NOW();

-- name: DeleteControlOwner :execrows
DELETE FROM organization.compliance_control_owners WHERE organization_id = @organization_id AND control_id = @control_id;

-- name: IsOrganizationMember :one
-- Whether the user is one of the organization's people: its own, or holding a role
-- there.
SELECT EXISTS (
    SELECT 1 FROM account.users u WHERE u.id = @user_id AND u.deleted_at IS NULL
      AND (u.organization_id = @organization_id OR EXISTS (
          SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.organization_id = @organization_id))
);

-- name: ListComplianceAudits :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, framework, kind, body, scope, reference, issued_on, expires_on, created_by, created_at
FROM organization.compliance_audits
WHERE organization_id = @organization_id AND (sqlc.narg('framework')::text IS NULL OR framework = sqlc.narg('framework'))
ORDER BY issued_on DESC, created_at DESC
LIMIT 1001;

-- name: InsertComplianceAudit :one
INSERT INTO organization.compliance_audits (organization_id, framework, kind, body, scope, reference, issued_on, expires_on, created_by)
VALUES (@organization_id, @framework, @kind, @body, @scope, @reference, @issued_on, sqlc.narg('expires_on'), sqlc.narg('created_by'))
RETURNING id, framework, kind, body, scope, reference, issued_on, expires_on, created_by, created_at;

-- name: DeleteComplianceAudit :one
DELETE FROM organization.compliance_audits WHERE id = @id AND organization_id = @organization_id
RETURNING framework, kind, body;
