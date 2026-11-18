-- Queries for the retention domain.
-- Static queries against organization.retention_policy and account.users live here
-- and are compiled by sqlc into ./dbgen.

-- name: GetRetentionPolicy :one
SELECT p.deleted_users_enabled, p.deleted_users_days, p.updated_at, p.updated_by, u.email AS updated_by_email
FROM organization.retention_policy p
LEFT JOIN account.users u ON u.id = p.updated_by
WHERE p.organization_id = $1;

-- Upsert an organization's retention policy and return the stored values.
-- name: UpsertRetentionPolicy :one
INSERT INTO organization.retention_policy (organization_id, deleted_users_enabled, deleted_users_days, updated_at, updated_by)
VALUES ($1, $2, $3, NOW(), sqlc.narg('updated_by'))
ON CONFLICT (organization_id) DO UPDATE SET
    deleted_users_enabled = EXCLUDED.deleted_users_enabled,
    deleted_users_days    = EXCLUDED.deleted_users_days,
    updated_at            = NOW(),
    updated_by            = EXCLUDED.updated_by
RETURNING deleted_users_enabled, deleted_users_days, updated_at;

-- Count soft-deleted users older than `days` days for a given organization.
-- The days value is clamped to [1,3650] by the caller before it reaches here.
-- name: CountRipeDeletedUsers :one
SELECT count(*)
FROM account.users
WHERE organization_id = $1
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => $2);

-- ListRipeDeletedUsers lists, in ID order after @after, at most @max_rows of
-- the organization's soft-deleted users older than @days days.
-- name: ListRipeDeletedUsers :many
SELECT id FROM account.users
WHERE organization_id = @organization_id
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => @days)
  AND id > @after
ORDER BY id
LIMIT @max_rows;

-- PurgeRipeDeletedUser permanently removes one of the organization's soft-deleted
-- users older than @days days.
-- name: PurgeRipeDeletedUser :execrows
DELETE FROM account.users
WHERE id = @id AND organization_id = @organization_id
  AND deleted_at IS NOT NULL
  AND deleted_at < NOW() - make_interval(days => @days);

-- name: ListEnabledRetentionPolicies :many
SELECT organization_id, deleted_users_days
FROM organization.retention_policy
WHERE deleted_users_enabled = TRUE;

-- -----------------------------------------------------------------------
-- Sweeps (sweeps.go): each deletes at most @max_rows rows nothing needs any
-- more from one table, and is run in batches until none are left.
-- -----------------------------------------------------------------------

-- name: SweepAuthorizationCodes :execrows
DELETE FROM auth.oidc_authorization_codes WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.oidc_authorization_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepConsentRequests :execrows
DELETE FROM auth.oidc_consent_requests WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.oidc_consent_requests c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepDeviceCodes :execrows
DELETE FROM auth.oidc_device_codes WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.oidc_device_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepBackchannelRequests :execrows
DELETE FROM auth.oidc_ciba_requests WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.oidc_ciba_requests c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepSignInLinks :execrows
DELETE FROM auth.magic_links WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.magic_links c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepPasswordResets :execrows
DELETE FROM auth.password_resets WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.password_resets c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepEmailVerifications :execrows
DELETE FROM account.email_verifications WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM account.email_verifications c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepPhoneVerifications :execrows
DELETE FROM account.phone_verifications WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM account.phone_verifications c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepSAMLRequests :execrows
DELETE FROM auth.saml_authn_requests WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.saml_authn_requests c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepFederatedSignInCodes :execrows
DELETE FROM auth.login_codes WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.login_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepFederatedSignInStates :execrows
DELETE FROM auth.oauth_states WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.oauth_states c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepPlatformSocialLinkCodes :execrows
DELETE FROM auth.platform_social_link_codes WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.platform_social_link_codes c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepConnectedAccountStates :execrows
DELETE FROM organization.token_vault_connect_states WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM organization.token_vault_connect_states c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepSecondFactorSignIns :execrows
DELETE FROM auth.mfa_login_challenges WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.mfa_login_challenges c WHERE c.expires_at < NOW() - INTERVAL '1 day' LIMIT @max_rows));

-- name: SweepFailedSignInCounts :execrows
DELETE FROM auth.login_attempts WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.login_attempts c
    WHERE c.last_failed_at < NOW() - INTERVAL '7 days' AND (c.locked_until IS NULL OR c.locked_until < NOW())
    LIMIT @max_rows));

-- name: SweepFailedSignInCountsByNetwork :execrows
DELETE FROM auth.login_attempts_by_network WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.login_attempts_by_network c
    WHERE c.last_failed_at < NOW() - INTERVAL '7 days' AND (c.locked_until IS NULL OR c.locked_until < NOW())
    LIMIT @max_rows));

-- name: SweepApplicationSecretFailures :execrows
DELETE FROM auth.oidc_client_auth_lockouts WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.oidc_client_auth_lockouts c
    WHERE c.last_failure_at < NOW() - INTERVAL '7 days' AND (c.locked_until IS NULL OR c.locked_until < NOW())
    LIMIT @max_rows));

-- name: SweepFailedSignInsBySource :execrows
DELETE FROM auth.login_source_failures WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.login_source_failures c WHERE c.last_failed_at < NOW() - INTERVAL '7 days' LIMIT @max_rows));

-- name: SweepSourceThrottles :execrows
DELETE FROM auth.login_source_throttles WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.login_source_throttles c WHERE c.throttled_until < NOW() - INTERVAL '7 days' LIMIT @max_rows));

-- name: SweepWebhookDeliveries :execrows
DELETE FROM organization.webhook_deliveries WHERE ctid = ANY(ARRAY(
    SELECT d.ctid FROM organization.webhook_deliveries d
    WHERE d.delivered_at < NOW() - INTERVAL '30 days' OR d.dead_at < NOW() - INTERVAL '30 days'
    LIMIT @max_rows));

-- name: SweepLogoutDeliveries :execrows
DELETE FROM auth.oidc_logout_deliveries WHERE ctid = ANY(ARRAY(
    SELECT d.ctid FROM auth.oidc_logout_deliveries d
    WHERE d.delivered_at < NOW() - INTERVAL '7 days' OR d.failed_at < NOW() - INTERVAL '7 days'
    LIMIT @max_rows));

-- name: SweepBotDetections :execrows
DELETE FROM auth.bot_events WHERE ctid = ANY(ARRAY(
    SELECT e.ctid FROM auth.bot_events e WHERE e.created_at < NOW() - INTERVAL '30 days' LIMIT @max_rows));

-- name: SweepSecurityEvents :execrows
DELETE FROM auth.security_events WHERE ctid = ANY(ARRAY(
    SELECT e.ctid FROM auth.security_events e
    WHERE e.resolved_at < NOW() - INTERVAL '90 days' OR e.created_at < NOW() - INTERVAL '365 days'
    LIMIT @max_rows));

-- name: SweepAuditAnomalies :execrows
DELETE FROM audit.anomalies WHERE ctid = ANY(ARRAY(
    SELECT a.ctid FROM audit.anomalies a
    WHERE a.resolved_at < NOW() - INTERVAL '90 days' OR a.created_at < NOW() - INTERVAL '365 days'
    LIMIT @max_rows));

-- name: SweepDirectorySyncEvents :execrows
DELETE FROM organization.directory_events WHERE ctid = ANY(ARRAY(
    SELECT e.ctid FROM organization.directory_events e WHERE e.started_at < NOW() - INTERVAL '90 days' LIMIT @max_rows));

-- name: SweepNotifications :execrows
DELETE FROM auth.notifications WHERE ctid = ANY(ARRAY(
    SELECT n.ctid FROM auth.notifications n WHERE n.created_at < NOW() - INTERVAL '90 days' LIMIT @max_rows));

-- name: SweepAccessDecisions :execrows
DELETE FROM auth.authz_decisions WHERE ctid = ANY(ARRAY(
    SELECT d.ctid FROM auth.authz_decisions d WHERE d.decided_at < NOW() - INTERVAL '30 days' LIMIT @max_rows));

-- name: SweepMonthlyActiveUsers :execrows
-- 13 months, so a year-on-year comparison and the last invoice's month remain.
DELETE FROM organization.monthly_active_users WHERE ctid = ANY(ARRAY(
    SELECT m.ctid FROM organization.monthly_active_users m
    WHERE m.month < (date_trunc('month', NOW() AT TIME ZONE 'UTC') - INTERVAL '13 months')::date LIMIT @max_rows));

-- name: SweepInvitations :execrows
DELETE FROM organization.invites WHERE ctid = ANY(ARRAY(
    SELECT i.ctid FROM organization.invites i WHERE i.expires_at < NOW() - INTERVAL '90 days' LIMIT @max_rows));

-- name: SweepApplicationGrants :execrows
-- Oldest first, so a token goes no later than the one it was renewed from.
DELETE FROM auth.oidc_refresh_tokens WHERE ctid = ANY(ARRAY(
    SELECT t.ctid FROM auth.oidc_refresh_tokens t WHERE t.grant_expires_at < NOW() - INTERVAL '7 days'
    ORDER BY t.issued_at, t.id LIMIT @max_rows));
