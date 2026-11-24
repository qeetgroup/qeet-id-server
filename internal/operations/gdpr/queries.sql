-- Queries for the gdpr domain: erasure and export requests, the erasure
-- itself, the person's export and a deleted organization's purge.
-- All queries are static.
--
-- InsertPurgeRequest uses @grace_until (a pre-computed timestamptz from Go)
-- instead of NOW() + $5::interval to avoid the text→interval cast, whose
-- generated parameter type is ambiguous between text and pgtype.Interval.
-- The value is identical: time.Now().UTC().Add(s.grace).

-- -----------------------------------------------------------------------
-- GDPR purge requests
-- -----------------------------------------------------------------------

-- name: InsertPurgeRequest :one
-- Queue a right-to-erasure request. grace_until is pre-computed in Go
-- (time.Now().UTC().Add(s.grace)) to avoid pgtype.Interval parameter type issues.
-- subject_id keeps the account's ID once the account itself is deleted, and
-- subject_email and subject_name who it was filed for until they are erased.
INSERT INTO account.purge_requests (organization_id, user_id, subject_id, requested_by, reason, grace_until,
                                   subject_email, subject_name)
SELECT @organization_id, @subject_id::uuid, @subject_id::uuid, @requested_by, @reason, @grace_until, u.email, u.display_name
FROM account.users u WHERE u.id = @subject_id::uuid AND u.organization_id = @organization_id
RETURNING id, organization_id, subject_id, requested_by, reason, status,
          grace_until, completed_at, created_at, subject_email, subject_name;

-- name: CancelPurgeRequest :one
-- Cancel a pending purge request (e.g. the subject changed their mind),
-- returning its user. No row when it is already completed or not found.
UPDATE account.purge_requests
SET status = 'cancelled'
WHERE id = @id AND organization_id = @organization_id AND status = 'pending'
RETURNING subject_id;

-- name: ListPurgeRequests :many
-- List all purge requests for an organization, most recent first.
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, subject_id, requested_by, reason, status,
       grace_until, completed_at, created_at, subject_email, subject_name
FROM account.purge_requests
WHERE organization_id = @organization_id
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

-- name: UserBelongsToOrganization :one
-- Whether organization_id is the user's home organization, not merely one
-- where they hold a role.
SELECT EXISTS (
    SELECT 1 FROM account.users WHERE id = @user_id AND organization_id = @organization_id::uuid
);

-- name: LeaseDuePurgeRequests :many
-- Leases to @lease_owner, until @lease_until, up to 50 pending requests whose
-- grace period has ended and that no other worker holds.
WITH candidates AS (
    SELECT id
    FROM account.purge_requests
    WHERE status = 'pending' AND grace_until <= NOW()
      AND (lease_until IS NULL OR lease_until <= NOW())
    ORDER BY grace_until, created_at
    LIMIT 50
    FOR UPDATE SKIP LOCKED
)
UPDATE account.purge_requests AS request
SET lease_owner = @lease_owner::uuid, lease_until = @lease_until::timestamptz
FROM candidates
WHERE request.id = candidates.id
RETURNING request.id, request.subject_id;

-- name: LockLeasedPurgeRequest :one
-- Locks a pending request @lease_owner holds, returning its organization.
SELECT organization_id
FROM account.purge_requests
WHERE id = @id AND subject_id = @subject_id AND status = 'pending' AND lease_owner = @lease_owner::uuid
FOR UPDATE;

-- name: LockAccountHome :one
-- Locks an account, returning its home organization (NULL for none).
SELECT organization_id FROM account.users WHERE id = @id FOR UPDATE;

-- name: QuarantinePurgeRequest :exec
-- Sets aside a leased request whose account's home is not the request's
-- organization.
UPDATE account.purge_requests
SET status = 'quarantined', quarantined_at = NOW(),
    quarantine_reason = 'organization ownership mismatch detected by worker',
    lease_owner = NULL, lease_until = NULL
WHERE id = @id AND status = 'pending' AND lease_owner = @lease_owner::uuid;

-- name: CompletePurgeRequest :execrows
-- Completes a leased request and forgets who it was filed for.
UPDATE account.purge_requests
SET status = 'completed', completed_at = NOW(), lease_owner = NULL, lease_until = NULL,
    subject_email = NULL, subject_name = NULL
WHERE id = @id AND status = 'pending' AND lease_owner = @lease_owner::uuid;

-- -----------------------------------------------------------------------
-- GDPR export requests
-- -----------------------------------------------------------------------

-- name: InsertExportRequest :one
-- subject_id keeps the account's ID once the account itself is deleted.
INSERT INTO account.export_requests (organization_id, user_id, subject_id, requested_by)
VALUES (@organization_id, @subject_id::uuid, @subject_id::uuid, @requested_by)
RETURNING id, organization_id, subject_id, requested_by, status, completed_at, created_at;

-- name: ListExportRequests :many
-- At most paging.MaxListItems+1 rows: the API truncates the rest.
SELECT id, organization_id, subject_id, requested_by, status, error, completed_at, created_at
FROM account.export_requests
WHERE organization_id = @organization_id
ORDER BY created_at DESC
LIMIT 1001;

-- name: GetExportRequest :one
SELECT id, organization_id, subject_id, requested_by, status, payload, error,
       completed_at, created_at
FROM account.export_requests
WHERE id = @id AND organization_id = @organization_id;

-- name: FailExportRequest :execrows
-- Mark an export request the worker holds the lease on as failed.
UPDATE account.export_requests
SET status = 'failed', error = @error_msg, completed_at = NOW(),
    lease_owner = NULL, lease_until = NULL
WHERE id = @id AND organization_id = @organization_id AND lease_owner = @lease_owner;

-- name: LeasePendingExportRequests :many
-- Leases to @lease_owner, until @lease_until, up to 20 pending requests no
-- other worker holds.
WITH candidates AS (
    SELECT id
    FROM account.export_requests
    WHERE status = 'pending' AND (lease_until IS NULL OR lease_until <= NOW())
    ORDER BY created_at
    LIMIT 20
    FOR UPDATE SKIP LOCKED
)
UPDATE account.export_requests AS request
SET lease_owner = @lease_owner::uuid, lease_until = @lease_until::timestamptz
FROM candidates
WHERE request.id = candidates.id
RETURNING request.id, request.organization_id, request.subject_id;

-- name: CompleteExportRequest :execrows
-- Stores the payload of a request @lease_owner holds and marks it ready.
UPDATE account.export_requests
SET status = 'ready', payload = @payload, completed_at = NOW(),
    lease_owner = NULL, lease_until = NULL
WHERE id = @id AND lease_owner = @lease_owner::uuid;

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
WHERE id = @user_id AND organization_id = @organization_id;

-- name: ListUserSessionsForExport :many
-- COALESCE ensures a non-null result for ip (inet is nullable; host() of NULL = NULL).
SELECT id, COALESCE(host(ip), '') AS ip, user_agent, created_at, last_seen_at, revoked_at
FROM auth.sessions
WHERE user_id = @user_id AND organization_id = @organization_id
ORDER BY created_at DESC;

-- name: ListUserPasskeysForExport :many
SELECT id, name, transports, created_at, last_used_at
FROM auth.passkey_credentials
WHERE user_id = @user_id;

-- name: ListUserRolesForExport :many
SELECT r.name AS role_name, ur.granted_at
FROM rbac.user_roles ur
JOIN rbac.roles r ON r.id = ur.role_id
WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id;

-- name: GetOwnProfileForExport :one
-- The person's own profile, whichever organization is their home.
SELECT email, phone, display_name, avatar_url, metadata, status, email_verified_at, phone_verified_at, created_at
FROM account.users
WHERE id = @user_id;

-- name: ListOwnSessionsForExport :many
-- The person's sessions in every organization.
SELECT id, COALESCE(host(ip), '')::text AS ip, user_agent, created_at, last_seen_at, revoked_at
FROM auth.sessions
WHERE user_id = @user_id
ORDER BY created_at DESC;

-- name: ListOwnRolesForExport :many
-- The person's roles in every organization, with the organization's name.
SELECT r.name AS role_name, t.name AS organization_name, ur.granted_at
FROM rbac.user_roles ur
JOIN rbac.roles r ON r.id = ur.role_id
JOIN organization.organizations t ON t.id = ur.organization_id
WHERE ur.user_id = @user_id
ORDER BY ur.granted_at;

-- name: GetUserMFAStatus :one
-- Return whether the user has a confirmed TOTP factor.
-- Explicit ::boolean cast ensures sqlc infers bool rather than interface{}.
SELECT (confirmed_at IS NOT NULL)::boolean AS mfa_enabled
FROM auth.mfa_totp
WHERE user_id = @user_id;

-- -----------------------------------------------------------------------
-- Export sections: one organization's part of the person's data when
-- organization_id is set (its export of a member), all of it when it is null (the
-- person's own export).
-- -----------------------------------------------------------------------

-- ListUserIdentitiesForExport lists the accounts linked for signing in: social
-- and single sign-on identities, and the platform's own social sign-ins.
-- name: ListUserIdentitiesForExport :many
SELECT i.provider, i.subject, i.email, i.linked_at
FROM account.external_identities i
WHERE i.user_id = @user_id AND (sqlc.narg('organization_id')::uuid IS NULL OR i.organization_id = sqlc.narg('organization_id'))
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
WHERE c.user_id = @user_id AND (sqlc.narg('organization_id')::uuid IS NULL OR cl.organization_id = sqlc.narg('organization_id'))
ORDER BY c.granted_at;

-- ListUserGrantsForExport lists the person's live application grants, by
-- their latest refresh token.
-- name: ListUserGrantsForExport :many
SELECT t.client_id, COALESCE(cl.name, '')::text AS client_name, t.scopes, t.issued_at, t.expires_at
FROM auth.oidc_refresh_tokens t
LEFT JOIN auth.oidc_clients cl ON cl.client_id = t.client_id
WHERE t.user_id = @user_id AND t.revoked_at IS NULL AND t.replaced_by IS NULL AND t.expires_at > NOW()
  AND (sqlc.narg('organization_id')::uuid IS NULL OR t.organization_id = sqlc.narg('organization_id'))
ORDER BY t.issued_at;

-- name: ListUserGroupsForExport :many
SELECT g.name, o.name AS organization, m.added_at
FROM organization.group_members m
JOIN organization.groups g ON g.id = m.group_id AND g.organization_id = m.organization_id
JOIN organization.organizations o ON o.id = m.organization_id
WHERE m.user_id = @user_id AND (sqlc.narg('organization_id')::uuid IS NULL OR m.organization_id = sqlc.narg('organization_id'))
ORDER BY m.added_at;

-- ListUserSignInsForExport lists the person's most recent sign-ins, made and
-- failed, from the audit trail.
-- name: ListUserSignInsForExport :many
SELECT e.created_at, (e.action = 'auth.login_succeeded')::boolean AS succeeded,
       COALESCE(e.metadata->>'method', '')::text AS method,
       COALESCE(host(e.ip), '')::text AS ip, COALESCE(e.user_agent, '')::text AS user_agent,
       COALESCE(o.name, '')::text AS organization
FROM audit.events e
LEFT JOIN organization.organizations o ON o.id = e.organization_id
WHERE e.actor_user_id = @user_id::uuid AND e.action IN ('auth.login_succeeded', 'auth.sign_in_failed')
  AND (sqlc.narg('organization_id')::uuid IS NULL OR e.organization_id = sqlc.narg('organization_id'))
ORDER BY e.created_at DESC
LIMIT 1000;

-- -----------------------------------------------------------------------
-- Organization purge (organizationpurge.go); its per-table deletes are
-- dynamic and stay there.
-- -----------------------------------------------------------------------

-- name: ListPurgeableOrganizations :many
-- Organizations deleted before @deleted_before, oldest first.
SELECT id FROM organization.organizations
WHERE status = 'deleted' AND deleted_at IS NOT NULL AND deleted_at < @deleted_before::timestamptz
ORDER BY deleted_at LIMIT @max_rows;

-- name: GetPurgeableOrganization :one
SELECT slug, deleted_at::timestamptz AS deleted_at FROM organization.organizations
WHERE id = @id AND status = 'deleted' AND deleted_at IS NOT NULL AND deleted_at < @deleted_before::timestamptz;

-- name: DeletePurgedOrganization :exec
-- What is left of the organization holds a foreign key that cascades.
DELETE FROM organization.organizations WHERE id = @id AND status = 'deleted';

-- name: RecordOrganizationPurge :exec
INSERT INTO platform.organization_purges (organization_id, slug, deleted_at, rows_purged, accounts_removed, accounts_detached)
VALUES (@organization_id, @slug, @deleted_at, @rows_purged, @accounts_removed::bigint, @accounts_detached::bigint)
ON CONFLICT (organization_id) DO UPDATE SET purged_at = NOW(), rows_purged = EXCLUDED.rows_purged,
    accounts_removed = EXCLUDED.accounts_removed, accounts_detached = EXCLUDED.accounts_detached;

-- name: ListHomeAccounts :many
-- The accounts whose home is the organization, and whether each still holds a
-- role in another one.
SELECT u.id, EXISTS (
    SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = u.id AND ur.organization_id <> @organization_id::uuid
)::boolean AS elsewhere
FROM account.users u WHERE u.organization_id = @organization_id::uuid;

-- name: DetachHomeAccount :exec
UPDATE account.users SET organization_id = NULL WHERE id = @id AND organization_id = @organization_id::uuid;

-- name: DeleteHomeAccount :exec
DELETE FROM account.users WHERE id = @id AND organization_id = @organization_id::uuid;

-- name: ListOrganizationTables :many
-- Every table with an organization_id whose foreign key to the organization
-- does not cascade, or that has none (the audit log among them).
SELECT c.oid::regclass::text AS table_name
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
WHERE c.relkind = 'r' AND c.relnamespace::regnamespace::text NOT IN ('pg_catalog', 'information_schema')
  AND c.oid NOT IN ('organization.organizations'::regclass, 'platform.organization_purges'::regclass)
  AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_constraint k
      WHERE k.conrelid = c.oid AND k.contype = 'f' AND k.confrelid = 'organization.organizations'::regclass
        AND k.confdeltype = 'c' AND k.conkey = ARRAY[a.attnum])
ORDER BY 1;

-- name: DeletePendingSignUps :exec
-- A sign-up waiting on the organization names it in another column.
DELETE FROM auth.webauthn_sessions WHERE pending_organization_id = @organization_id;

-- -----------------------------------------------------------------------
-- Erasure (erasure.go): what an erased account leaves outside its user row
-- and the audit trail, by its ID, then by its address (lowercased).
-- -----------------------------------------------------------------------

-- name: ErasePasskeyCredentials :exec
DELETE FROM auth.passkey_credentials WHERE user_id = @user_id::uuid;

-- name: EraseWebAuthnSessions :exec
DELETE FROM auth.webauthn_sessions WHERE user_id = @user_id::uuid;

-- name: EraseMFAOTPFactors :exec
DELETE FROM auth.mfa_otp_factors WHERE user_id = @user_id::uuid;

-- name: EraseMFAPushPairings :exec
DELETE FROM auth.mfa_push_pairings WHERE user_id = @user_id::uuid;

-- name: EraseMFAPushChallenges :exec
DELETE FROM auth.mfa_push_challenges WHERE user_id = @user_id::uuid;

-- name: EraseMFAPushDevices :exec
DELETE FROM auth.mfa_push_devices WHERE user_id = @user_id::uuid;

-- name: EraseMFAVerifications :exec
DELETE FROM auth.mfa_verifications WHERE user_id = @user_id::uuid;

-- name: EraseMFALoginChallenges :exec
DELETE FROM auth.mfa_login_challenges WHERE user_id = @user_id::uuid;

-- name: EraseMFAAttemptBudgets :exec
DELETE FROM auth.mfa_attempt_budgets WHERE user_id = @user_id::uuid;

-- name: EraseMFAFailureStreaks :exec
DELETE FROM auth.mfa_failure_streaks WHERE user_id = @user_id::uuid;

-- name: EraseTrustedDevices :exec
DELETE FROM auth.trusted_devices WHERE user_id = @user_id::uuid;

-- name: EraseSessions :exec
DELETE FROM auth.sessions WHERE user_id = @user_id::uuid;

-- name: EraseLoginSessions :exec
DELETE FROM auth.login_sessions WHERE user_id = @user_id::uuid;

-- name: EraseLoginContextHistory :exec
DELETE FROM auth.login_context_history WHERE user_id = @user_id::uuid;

-- name: EraseRefreshTokens :exec
DELETE FROM auth.oidc_refresh_tokens WHERE user_id = @user_id::uuid;

-- name: EraseConsents :exec
DELETE FROM auth.oidc_consents WHERE user_id = @user_id::uuid;

-- name: EraseConsentRequests :exec
DELETE FROM auth.oidc_consent_requests WHERE user_id = @user_id::uuid;

-- name: EraseAuthorizationCodes :exec
DELETE FROM auth.oidc_authorization_codes WHERE user_id = @user_id::uuid;

-- name: EraseDeviceCodes :exec
DELETE FROM auth.oidc_device_codes WHERE user_id = @user_id::uuid;

-- name: EraseBackchannelRequests :exec
DELETE FROM auth.oidc_ciba_requests WHERE user_id = @user_id::uuid;

-- name: EraseLoginCodes :exec
DELETE FROM auth.login_codes WHERE user_id = @user_id::uuid;

-- name: ErasePlatformSocialLinkCodes :exec
DELETE FROM auth.platform_social_link_codes WHERE user_id = @user_id::uuid;

-- name: EraseOAuthLinkStates :exec
DELETE FROM auth.oauth_states WHERE link_user_id = @user_id::uuid;

-- name: ErasePlatformSocialIdentities :exec
DELETE FROM auth.platform_social_identities WHERE user_id = @user_id::uuid;

-- name: EraseExternalIdentities :exec
DELETE FROM account.external_identities WHERE user_id = @user_id::uuid;

-- name: ErasePasswordCredentials :exec
DELETE FROM auth.password_credentials WHERE user_id = @user_id::uuid;

-- name: ErasePasswordResets :exec
DELETE FROM auth.password_resets WHERE user_id = @user_id::uuid;

-- name: EraseMFATOTP :exec
DELETE FROM auth.mfa_totp WHERE user_id = @user_id::uuid;

-- name: EraseMFARecoveryCodes :exec
DELETE FROM auth.mfa_recovery_codes WHERE user_id = @user_id::uuid;

-- name: EraseEmailVerifications :exec
DELETE FROM account.email_verifications WHERE user_id = @user_id::uuid;

-- name: ErasePhoneVerifications :exec
DELETE FROM account.phone_verifications WHERE user_id = @user_id::uuid;

-- name: EraseAPIKeys :exec
DELETE FROM auth.api_keys WHERE user_id = @user_id::uuid;

-- name: EraseNotifications :exec
DELETE FROM auth.notifications WHERE user_id = @user_id::uuid;

-- name: EraseTokenVaultGrants :exec
DELETE FROM organization.token_vault_grants WHERE user_id = @user_id::uuid;

-- name: EraseTokenVaultConnectStates :exec
DELETE FROM organization.token_vault_connect_states WHERE user_id = @user_id::uuid;

-- name: EraseDirectoryProfiles :exec
DELETE FROM organization.directory_profiles WHERE user_id = @user_id::uuid;

-- name: EraseDirectoryAlerts :exec
DELETE FROM organization.directory_alerts WHERE user_id = @user_id::uuid;

-- name: EraseGroupMemberships :exec
DELETE FROM organization.group_members WHERE user_id = @user_id::uuid;

-- name: EraseSAMLAppAssignments :exec
DELETE FROM organization.saml_sp_user_assignments WHERE user_id = @user_id::uuid;

-- name: EraseSAMLPersistentIDs :exec
DELETE FROM organization.saml_idp_persistent_ids WHERE user_id = @user_id::uuid;

-- name: EraseBreakGlassMemberships :exec
DELETE FROM organization.break_glass_members WHERE user_id = @user_id::uuid;

-- name: EraseRoleAssignments :exec
DELETE FROM rbac.user_roles WHERE user_id = @user_id::uuid;

-- name: EraseActorBaseline :exec
DELETE FROM audit.actor_baselines WHERE actor_user_id = @user_id::uuid;

-- name: EraseAIConversations :exec
DELETE FROM qeetai.conversations WHERE user_id = @user_id::uuid;

-- name: RevokeIssuedCredentials :exec
-- A credential issued to the person is revoked and its claims cleared; the row
-- stays so a verifier still learns it is revoked.
UPDATE auth.credentials
SET subject = 'erased', claims = '{}', revoked_at = COALESCE(revoked_at, NOW()), user_id = NULL
WHERE user_id = @user_id::uuid;

-- name: DropExportPayloads :exec
UPDATE account.export_requests
SET payload = NULL, lease_owner = NULL, lease_until = NULL,
    status = CASE status WHEN 'pending' THEN 'failed' WHEN 'ready' THEN 'expired' ELSE status END,
    error = CASE status WHEN 'pending' THEN 'The account was erased.' ELSE error END,
    completed_at = COALESCE(completed_at, NOW())
WHERE user_id = @user_id::uuid AND (payload IS NOT NULL OR status = 'pending');

-- name: EraseMagicLinksTo :exec
DELETE FROM auth.magic_links WHERE lower(email) = @email::text;

-- name: EraseLoginAttemptsOf :exec
DELETE FROM auth.login_attempts WHERE email = @email::text;

-- name: EraseNetworkLoginAttemptsOf :exec
DELETE FROM auth.login_attempts_by_network WHERE email = @email::text;

-- name: EraseSourceFailuresOf :exec
DELETE FROM auth.login_source_failures WHERE email = @email::text;

-- name: EraseSpentInvitesTo :exec
DELETE FROM organization.invites WHERE lower(email) = @email::text AND (status <> 'pending' OR expires_at <= NOW());
