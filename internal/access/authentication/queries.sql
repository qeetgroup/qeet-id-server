-- Queries for the authentication domain, compiled by sqlc into ./dbgen. A
-- NULL-able organization_id is a *uuid.UUID: nil is no organization.

-- Sign-in lockout (lockout.go). Every timestamp is the caller's @now, so one
-- attempt is judged against a single instant. Keys: @email is the lowercased
-- address (whether or not an account has it); @network the source network.

-- name: GetSignInLocks :one
-- In one round trip: until when the source network is throttled, and until
-- when the account is locked for that network and everywhere. NULL = not.
SELECT t.throttled_until AS source_throttled_until,
       n.locked_until    AS network_locked_until,
       a.locked_until    AS account_locked_until
FROM (SELECT 1) AS attempt
LEFT JOIN auth.login_source_throttles t
       ON t.network = @network AND t.throttled_until > @now::timestamptz
LEFT JOIN auth.login_attempts_by_network n
       ON n.email = @email AND n.network = @network AND n.locked_until > @now::timestamptz
LEFT JOIN auth.login_attempts a
       ON a.email = @email AND a.locked_until > @now::timestamptz;

-- name: RecordNetworkFailure :one
-- Counts a failure for the account from one network. The count starts afresh
-- when the last failure is older than the window or a lock has run its
-- course; reaching @threshold sets the lock (an active lock is kept as is).
-- locked_until = @lock_until on return means this failure set the lock.
INSERT INTO auth.login_attempts_by_network AS c
    (email, network, failed_count, first_failed_at, last_failed_at, locked_until)
VALUES (@email, @network, 1, @now::timestamptz, @now::timestamptz,
        CASE WHEN @threshold::int4 <= 1 THEN @lock_until::timestamptz END)
ON CONFLICT (email, network) DO UPDATE SET
    failed_count = CASE
        WHEN c.last_failed_at < @window_start::timestamptz OR c.locked_until <= @now::timestamptz THEN 1
        ELSE c.failed_count + 1 END,
    first_failed_at = CASE
        WHEN c.last_failed_at < @window_start::timestamptz OR c.locked_until <= @now::timestamptz THEN @now::timestamptz
        ELSE c.first_failed_at END,
    last_failed_at = @now::timestamptz,
    locked_until = CASE
        WHEN c.locked_until > @now::timestamptz THEN c.locked_until
        WHEN (CASE
            WHEN c.last_failed_at < @window_start::timestamptz OR c.locked_until <= @now::timestamptz THEN 1
            ELSE c.failed_count + 1 END) >= @threshold::int4 THEN @lock_until::timestamptz
        ELSE NULL END
RETURNING failed_count, locked_until;

-- name: RecordAccountFailure :one
-- RecordNetworkFailure for the account alone, whichever network failed.
INSERT INTO auth.login_attempts AS c
    (email, failed_count, first_failed_at, last_failed_at, locked_until)
VALUES (@email, 1, @now::timestamptz, @now::timestamptz,
        CASE WHEN @threshold::int4 <= 1 THEN @lock_until::timestamptz END)
ON CONFLICT (email) DO UPDATE SET
    failed_count = CASE
        WHEN c.last_failed_at < @window_start::timestamptz OR c.locked_until <= @now::timestamptz THEN 1
        ELSE c.failed_count + 1 END,
    first_failed_at = CASE
        WHEN c.last_failed_at < @window_start::timestamptz OR c.locked_until <= @now::timestamptz THEN @now::timestamptz
        ELSE c.first_failed_at END,
    last_failed_at = @now::timestamptz,
    locked_until = CASE
        WHEN c.locked_until > @now::timestamptz THEN c.locked_until
        WHEN (CASE
            WHEN c.last_failed_at < @window_start::timestamptz OR c.locked_until <= @now::timestamptz THEN 1
            ELSE c.failed_count + 1 END) >= @threshold::int4 THEN @lock_until::timestamptz
        ELSE NULL END
RETURNING failed_count, locked_until;

-- name: RecordSourceFailure :exec
-- Remembers that a source network failed to sign in to an account.
INSERT INTO auth.login_source_failures (network, email, last_failed_at)
VALUES (@network, @email, @now::timestamptz)
ON CONFLICT (network, email) DO UPDATE SET last_failed_at = EXCLUDED.last_failed_at;

-- name: ForgetSourceFailuresBefore :exec
DELETE FROM auth.login_source_failures
WHERE network = @network AND last_failed_at < @window_start::timestamptz;

-- name: CountSourceAccounts :one
-- Distinct accounts the network failed against (stale rows already forgotten).
SELECT COUNT(*) FROM auth.login_source_failures WHERE network = @network;

-- name: ThrottleSource :one
-- Throttles a source network unless it already is: no row on return means
-- another attempt set the throttle first.
INSERT INTO auth.login_source_throttles AS t (network, throttled_at, throttled_until, distinct_accounts)
VALUES (@network, @now::timestamptz, @throttled_until::timestamptz, @distinct_accounts::int4)
ON CONFLICT (network) DO UPDATE SET
    throttled_at      = EXCLUDED.throttled_at,
    throttled_until   = EXCLUDED.throttled_until,
    distinct_accounts = EXCLUDED.distinct_accounts
WHERE t.throttled_until <= EXCLUDED.throttled_at
RETURNING throttled_until;

-- name: TakeSourceAccounts :many
-- The accounts a source was just throttled for; it starts afresh once the
-- throttle lifts.
DELETE FROM auth.login_source_failures WHERE network = @network RETURNING email;

-- name: ClearSignInFailures :exec
-- After a successful sign-in: forget the account's failures from this network
-- and its account-wide count. Other networks' counts stay.
WITH by_network AS (
    DELETE FROM auth.login_attempts_by_network n WHERE n.email = @email AND n.network = @network
)
DELETE FROM auth.login_attempts a WHERE a.email = @email;

-- name: GetClientOrganization :one
-- The organization an OAuth client belongs to (whose policy a hosted sign-in for it
-- is held to).
SELECT organization_id FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: InsertLoginSession :one
-- second_factor: how the sign-in met a second factor (NULL: it didn't); see
-- migration 0149.
INSERT INTO auth.login_sessions (token_hash, user_id, expires_at, ip, user_agent, second_factor)
VALUES (@token_hash, @user_id, @expires_at, NULLIF(@ip::text, '')::inet, @user_agent,
        NULLIF(@second_factor::text, ''))
RETURNING id;

-- name: LoginSessionSecondFactor :one
-- How the sign-in behind a live hosted-login session of the user's met a
-- second factor ('' when it didn't). No row when the session is unknown,
-- someone else's or expired.
SELECT COALESCE(second_factor, '')::text AS second_factor
FROM auth.login_sessions
WHERE id = @id AND user_id = @user_id AND expires_at > NOW();

-- name: SessionSecondFactor :one
-- How the sign-in behind a live session of the user's met a second factor
-- ('' when it didn't), and whether the session holds a step-up still inside
-- its organization's window. No row when the session is unknown, someone
-- else's, revoked or expired.
SELECT COALESCE(s.second_factor, '')::text AS second_factor,
       EXISTS (
           SELECT 1 FROM auth.mfa_verifications v
           WHERE v.session_id = s.id
             AND v.verified_at > NOW() - COALESCE(sp.step_up_window, INTERVAL '5 minutes')
       ) AS stepped_up
FROM auth.sessions s
LEFT JOIN organization.security_policies sp ON sp.organization_id = s.organization_id
WHERE s.id = @session_id AND s.user_id = @user_id AND s.revoked_at IS NULL
  AND s.expires_at > NOW() AND s.last_seen_at + s.idle_timeout > NOW();

-- GetLoginSession is the hosted-login session a cookie names, unless its user is
-- suspended or deleted: however it was suspended, a suspended person's browser
-- signs in nothing.
-- name: GetLoginSession :one
SELECT s.id, s.user_id, s.expires_at, s.created_at
FROM auth.login_sessions s
JOIN account.users u ON u.id = s.user_id
WHERE s.token_hash = @token_hash AND u.status = 'active' AND u.deleted_at IS NULL;

-- name: GetLoginSessionUser :one
-- The user behind a live hosted-login session, and their own organization (NULL
-- for a user without one), when the sign-in happened, and how it met a second
-- factor ('' when it didn't). No row when the session is unknown or expired,
-- or the user or their organization is no longer active.
SELECT s.user_id, u.organization_id, s.created_at, COALESCE(s.second_factor, '')::text AS second_factor
FROM auth.login_sessions s
JOIN account.users u ON u.id = s.user_id
LEFT JOIN organization.organizations t ON t.id = u.organization_id
WHERE s.token_hash = @token_hash
  AND s.expires_at > NOW()
  AND u.status = 'active' AND u.deleted_at IS NULL
  AND (u.organization_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL));

-- EndLoginSession ends the hosted-login (browser) session behind a cookie —
-- expired or not, since what it started can outlive it — and returns its id,
-- its user and that user's own organization (NULL for none), so the sign-out
-- can end what the session started and record it. No row: nothing to end.
-- name: EndLoginSession :one
WITH ended AS (
    DELETE FROM auth.login_sessions WHERE token_hash = @token_hash
    RETURNING id, user_id
)
SELECT ended.id, ended.user_id, u.organization_id
FROM ended LEFT JOIN account.users u ON u.id = ended.user_id;

-- ExpireAuthorizationCodesForLoginSession spends every code minted through
-- the session that no application has redeemed yet, so none can be traded
-- for a grant after sign-out. A redemption already under way holds its code
-- locked and writes its grant before releasing it; this waits for it, skips
-- the code it spent, and the grant is ended by RevokeAppGrantsForLoginSession,
-- which runs after.
-- name: ExpireAuthorizationCodesForLoginSession :execrows
UPDATE auth.oidc_authorization_codes SET used_at = NOW()
WHERE login_session_id = @login_session_id AND used_at IS NULL;

-- RevokeAppGrantsForLoginSession ends the application grants the session
-- started — every not-yet-revoked token in their chains, renewals included —
-- and returns how many rows it touched and how many were the live head of a
-- grant (the number of grants it ended), like RevokeAppGrantsForUser.
-- name: RevokeAppGrantsForLoginSession :one
WITH ended AS (
    UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
    WHERE login_session_id = @login_session_id AND revoked_at IS NULL
    RETURNING used_at, expires_at
)
SELECT COUNT(*)::bigint AS touched,
       COUNT(*) FILTER (WHERE used_at IS NULL AND expires_at > NOW())::bigint AS live
FROM ended;

-- name: TouchTrustedDevice :one
-- Refreshes last_used_at on the live device the token names for the user in
-- the organization that remembered it, and returns its id; no row otherwise.
UPDATE auth.trusted_devices SET last_used_at = NOW()
WHERE token_hash = @token_hash AND user_id = @user_id AND organization_id = @organization_id AND expires_at > NOW()
RETURNING id;

-- PurgeExpiredTrustedDevices deletes at most @max_rows remembered devices that
-- expired before the cutoff; they no longer skip anything.
-- name: PurgeExpiredTrustedDevices :execrows
DELETE FROM auth.trusted_devices WHERE ctid = ANY(ARRAY(
    SELECT d.ctid FROM auth.trusted_devices d WHERE d.expires_at < @cutoff LIMIT @max_rows));

-- CheckOrganizationMembership reports whether an active account is a member of an
-- active organization: the organization's own account, or holding a role there.
-- name: CheckOrganizationMembership :one
SELECT EXISTS (
    SELECT 1 FROM account.users account
    JOIN organization.organizations organization ON organization.id = @organization_id::uuid
    WHERE account.id = @user_id
      AND account.status = 'active' AND account.deleted_at IS NULL
      AND organization.status = 'active' AND organization.deleted_at IS NULL
      AND (account.organization_id = organization.id
           OR EXISTS (SELECT 1 FROM rbac.user_roles membership
                      WHERE membership.organization_id = organization.id AND membership.user_id = account.id))
) AS is_member;

-- name: UpdatePasswordCredentialHash :exec
UPDATE auth.password_credentials SET password_hash = @password_hash, updated_at = NOW()
WHERE user_id = @user_id;

-- RevokeOtherSessionsForUser revokes all of a user's active sessions except the
-- one they're currently on — used after a password change/set so a compromised
-- session can't survive the credential rotation. A session past its maximum age
-- or idle timeout has already ended and is left as expired.
-- name: RevokeOtherSessionsForUser :many
UPDATE auth.sessions SET revoked_at = NOW()
WHERE user_id = @user_id AND id <> @keep_session_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
RETURNING id, organization_id;

-- SupersedeSession ends the session a switch of organization was made from —
-- only while it is live (not revoked, not past its maximum age or idle timeout)
-- and the caller's own — and records the session that replaced it. Ending it
-- is what stops its refresh tokens. Returns the organization it belonged to
-- (NULL for none). No row: it had already ended.
-- name: SupersedeSession :one
UPDATE auth.sessions SET revoked_at = NOW(), superseded_by = @new_session_id
WHERE id = @session_id AND user_id = @user_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
RETURNING organization_id;

-- SessionEnd is when one of the user's sessions ends however active it is.
-- No row: not theirs.
-- name: SessionEnd :one
SELECT expires_at FROM auth.sessions WHERE id = @session_id AND user_id = @user_id;

-- LockUserForSessionRevocation row-locks the account so bulk session
-- revocations for one user (and password changes, which lock the same row FOR
-- UPDATE) run one at a time. NO KEY UPDATE rather than UPDATE: creating a
-- session takes only the foreign key's KEY SHARE lock on this row, so sign-ins
-- are never blocked or deadlocked by it. pgx.ErrNoRows for an unknown user.
-- name: LockUserForSessionRevocation :one
SELECT id FROM account.users WHERE id = @user_id FOR NO KEY UPDATE;

-- IsSessionLiveForUser reports whether the session exists, belongs to the
-- user, has not been revoked and is not past its maximum age or idle timeout.
-- name: IsSessionLiveForUser :one
SELECT EXISTS (
    SELECT 1 FROM auth.sessions
    WHERE id = @session_id AND user_id = @user_id AND revoked_at IS NULL
      AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
) AS live;

-- IsSessionOfUser reports whether the session is (or was) one of the user's
-- own sessions, whether or not it has ended since.
-- name: IsSessionOfUser :one
SELECT EXISTS (
    SELECT 1 FROM auth.sessions
    WHERE id = @session_id AND user_id = @user_id
) AS owned;

-- RevokeAllSessionsForUser ends every live session of the user, the caller's
-- own included. Ending a session is what kills its refresh tokens. A session
-- past its maximum age or idle timeout has already ended and is left as expired.
-- name: RevokeAllSessionsForUser :many
UPDATE auth.sessions SET revoked_at = NOW()
WHERE user_id = @user_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
RETURNING id, organization_id;


-- RevokeAppGrantsForUser ends every application grant (OIDC refresh-token
-- chain) the user holds, for every application. It marks every not-yet-revoked
-- token of the user revoked — rotated-away ones too, so presenting an old one
-- later reads as revoked rather than as theft — and returns how many rows it
-- touched (touched) and how many were the live head of a grant (live: unused
-- and unexpired), which is the number of grants it ended.
-- name: RevokeAppGrantsForUser :one
WITH ended AS (
    UPDATE auth.oidc_refresh_tokens SET revoked_at = NOW()
    WHERE user_id = @user_id AND revoked_at IS NULL
    RETURNING used_at, expires_at
)
SELECT COUNT(*)::bigint AS touched,
       COUNT(*) FILTER (WHERE used_at IS NULL AND expires_at > NOW())::bigint AS live
FROM ended;

-- name: InsertRefreshToken :one
INSERT INTO auth.refresh_tokens (session_id, token_hash, expires_at)
VALUES (@session_id, @token_hash, @expires_at)
RETURNING id;

-- name: MarkRefreshTokenUsed :exec
UPDATE auth.refresh_tokens SET used_at = NOW(), replaced_by = @replaced_by WHERE id = @id;

-- UpdateSessionLastSeen records a renewal as the session's latest use and
-- returns when it now ends unless renewed again (never after it ends anyway).
-- name: UpdateSessionLastSeen :one
UPDATE auth.sessions SET last_seen_at = NOW() WHERE id = @session_id
RETURNING LEAST(last_seen_at + idle_timeout, expires_at)::timestamptz AS idle_expires_at;

-- name: RevokeSessionById :exec
-- Idempotent: no-op on an already-revoked session.
UPDATE auth.sessions SET revoked_at = NOW()
WHERE id = @session_id AND revoked_at IS NULL;

-- name: RevokeSessionForUser :one
-- Revokes a session scoped to its owner and returns the (nullable) organization for
-- event emission. No row (pgx.ErrNoRows) means the session isn't the caller's
-- or has already ended (revoked, or past its maximum age or idle timeout) — a
-- safe no-op, never a cross-user takedown.
UPDATE auth.sessions SET revoked_at = NOW()
WHERE id = @session_id AND user_id = @user_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
RETURNING organization_id;

-- name: InsertPasswordCredential :exec
-- Stores the Argon2id hash for a newly created identity (signup / hosted register).
INSERT INTO auth.password_credentials (user_id, password_hash)
VALUES (@user_id, @password_hash);

-- name: InsertOrganizationlessUser :one
-- Organization-less signup: creates the identity with organization_id NULL (a literal, not a
-- bind — membership lives in rbac.user_roles). display_name is nullable text.
INSERT INTO account.users (organization_id, email, display_name)
VALUES (NULL, @email, @display_name)
RETURNING id, created_at, updated_at;

-- name: InsertOrganizationlessSession :one
-- Organization-less session: organization_id is a literal NULL (not a bind). ip goes through
-- NULLIF so an empty string stores as SQL NULL, matching InsertLoginSession.
-- With no organization, the platform's session bounds apply. Returns when it
-- ends however active, and when it ends unless renewed.
INSERT INTO auth.sessions (id, user_id, organization_id, ip, user_agent, expires_at, idle_timeout, country, city)
VALUES (@id, @user_id, NULL, NULLIF(@ip::text, '')::inet, @user_agent,
        NOW() + make_interval(secs => @max_age_seconds::float8),
        make_interval(secs => @idle_seconds::float8),
        NULLIF(@country::text, ''), NULLIF(@city::text, ''))
RETURNING expires_at, LEAST(last_seen_at + idle_timeout, expires_at)::timestamptz AS idle_expires_at;

-- name: DeleteMFALoginChallenge :exec
DELETE FROM auth.mfa_login_challenges WHERE id = @id;

-- PurgeEndedSessions deletes at most @max_rows API and console sessions past
-- retention: ended (revoked) before the cutoff, or never ended but past its
-- maximum age or idle timeout before the cutoff, or with every refresh token
-- expired before it (none was usable after it). A session opened after the
-- cutoff is always kept. Their refresh tokens go with them (cascade). Returns
-- what it deleted; expired marks the sessions that were never ended, which are
-- announced as expired.
-- name: PurgeEndedSessions :many
DELETE FROM auth.sessions s
WHERE s.ctid = ANY(ARRAY(
    SELECT e.ctid FROM auth.sessions e
    WHERE e.created_at < @cutoff
      AND (
          (e.revoked_at IS NOT NULL AND e.revoked_at < @cutoff)
          OR (e.revoked_at IS NULL AND (
              e.expires_at < @cutoff
              OR e.last_seen_at + e.idle_timeout < @cutoff
              OR NOT EXISTS (
                  SELECT 1 FROM auth.refresh_tokens rt
                  WHERE rt.session_id = e.id AND rt.expires_at >= @cutoff)))
      )
    LIMIT @max_rows))
RETURNING s.id, s.user_id, s.organization_id, (s.revoked_at IS NULL)::boolean AS expired;

-- PurgeExpiredCeremonies deletes passkey ceremony state that has expired
-- unfinished — every sign-in page now starts one in the background, and most
-- are never completed. An expired ceremony can no longer be finished.
-- name: PurgeExpiredCeremonies :execrows
DELETE FROM auth.webauthn_sessions WHERE ctid = ANY(ARRAY(
    SELECT w.ctid FROM auth.webauthn_sessions w WHERE w.expires_at < NOW() LIMIT @max_rows));

-- PurgeExpiredLoginSessions deletes at most @max_rows hosted-login sessions
-- that expired before the cutoff. Their cookie stopped being sent when they
-- expired.
-- name: PurgeExpiredLoginSessions :execrows
DELETE FROM auth.login_sessions WHERE ctid = ANY(ARRAY(
    SELECT l.ctid FROM auth.login_sessions l WHERE l.expires_at < @cutoff LIMIT @max_rows));

-- DeleteTrustedDevicesForUser forgets every device remembered for the user, so
-- each is asked for the second factor again at its next sign-in.
-- name: DeleteTrustedDevicesForUser :execrows
DELETE FROM auth.trusted_devices WHERE user_id = @user_id;

-- SpendAuthorizationCodesForUser spends every authorisation code issued to the
-- user that no application has redeemed. A redemption already under way holds
-- its code locked and writes its grant first; this waits for it, and the grant
-- passes that follow end that grant.
-- name: SpendAuthorizationCodesForUser :execrows
UPDATE auth.oidc_authorization_codes SET used_at = NOW()
WHERE user_id = @user_id AND used_at IS NULL;

-- DenyDeviceAuthorizationsForUser denies every device sign-in the user approved
-- that the device has not collected yet.
-- name: DenyDeviceAuthorizationsForUser :execrows
UPDATE auth.oidc_device_codes SET status = 'denied'
WHERE user_id = @user_id AND consumed_at IS NULL AND status IN ('pending', 'authorized');

-- DenyBackchannelRequestsForUser denies every back-channel sign-in request for
-- the user that is pending, or approved but not yet collected.
-- name: DenyBackchannelRequestsForUser :execrows
UPDATE auth.oidc_ciba_requests SET status = 'denied'
WHERE user_id = @user_id AND consumed_at IS NULL AND status IN ('pending', 'authorized');

-- TouchSession records a use of a live session: last_seen_at, from which its
-- idle timeout counts, moves to now. A session that has ended — revoked, or
-- past its maximum age or idle timeout — is never revived. Writes at most
-- once a minute per session.
-- name: TouchSession :exec
UPDATE auth.sessions SET last_seen_at = NOW()
WHERE id = @session_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
  AND last_seen_at < NOW() - INTERVAL '1 minute';

-- MFARequirement reads what decides whether an account must use a second
-- factor to sign in to an organization: the account's own flag, the
-- organization's requirement and grace period, and whether the account is an
-- administrator there — holds the owner role or a role granting a permission
-- outside member_permissions, directly or through a group (with none listed,
-- any permission does).
-- name: MFARequirement :one
-- joined_at is when the account joined the organization, which the grace
-- period is judged by: its creation for its own organization, its first role
-- there for any other.
SELECT u.mfa_required,
       (CASE WHEN u.organization_id = @organization_id::uuid THEN u.created_at
             ELSE COALESCE((SELECT MIN(ur.granted_at) FROM rbac.user_roles ur
                            WHERE ur.user_id = u.id AND ur.organization_id = @organization_id::uuid), u.created_at)
        END)::timestamptz AS joined_at,
       COALESCE(sp.mfa_enforcement, 'optional')::text AS enforcement,
       COALESCE(sp.mfa_grace_days, 0)::int AS grace_days,
       sp.mfa_enforced_since,
       EXISTS (
           SELECT 1
           FROM rbac.user_roles ur
           JOIN rbac.roles ro ON ro.id = ur.role_id AND ro.organization_id = ur.organization_id
           LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
           LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
           WHERE ur.user_id = u.id AND ur.organization_id = @organization_id
             AND ((ro.is_system AND ro.name = 'owner')
                  OR (p.key IS NOT NULL AND NOT (p.key = ANY(COALESCE(@member_permissions::text[], '{}')))))
           UNION ALL
           SELECT 1
           FROM organization.group_members gm
           JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.organization_id = gm.organization_id
           JOIN rbac.roles ro ON ro.id = gr.role_id AND ro.organization_id = gr.organization_id
           LEFT JOIN rbac.role_permissions rp ON rp.role_id = ro.id
           LEFT JOIN rbac.permissions p ON p.id = rp.permission_id
           WHERE gm.user_id = u.id AND gm.organization_id = @organization_id
             AND ((ro.is_system AND ro.name = 'owner')
                  OR (p.key IS NOT NULL AND NOT (p.key = ANY(COALESCE(@member_permissions::text[], '{}')))))
       ) AS is_admin
FROM account.users u
LEFT JOIN organization.security_policies sp ON sp.organization_id = @organization_id
WHERE u.id = @user_id;

-- ExpireRecoveryLinksForUser ends the user's unused password-reset links and
-- the unused sign-in links to their address, set a minute back so a clock
-- behind the database's sees them ended too.
-- name: ExpireRecoveryLinksForUser :exec
WITH resets AS (
    UPDATE auth.password_resets SET expires_at = NOW() - INTERVAL '1 minute'
    WHERE user_id = @user_id AND used_at IS NULL AND expires_at > NOW() - INTERVAL '1 minute'
)
UPDATE auth.magic_links SET expires_at = NOW() - INTERVAL '1 minute'
WHERE LOWER(email) = (SELECT LOWER(u.email) FROM account.users u WHERE u.id = @user_id)
  AND used_at IS NULL AND expires_at > NOW() - INTERVAL '1 minute';

-- CountMFAAttempt counts one more second-factor attempt in the user's run of
-- wrong answers, which a right one ends, and returns the run and whether
-- their second-factor sign-in is already locked.
-- name: CountMFAAttempt :one
INSERT INTO auth.mfa_failure_streaks (user_id, failures) VALUES (@user_id, 1)
ON CONFLICT (user_id) DO UPDATE SET failures = auth.mfa_failure_streaks.failures + 1
RETURNING failures, (locked_at IS NOT NULL)::bool AS locked;

-- LockMFASignIn locks the user's second-factor sign-in, at the end of a run of
-- wrong answers.
-- name: LockMFASignIn :exec
UPDATE auth.mfa_failure_streaks SET locked_at = NOW() WHERE user_id = @user_id;

-- EndMFAFailureStreak ends the user's run of wrong answers, and any lock it
-- set.
-- name: EndMFAFailureStreak :exec
DELETE FROM auth.mfa_failure_streaks WHERE user_id = @user_id;

-- SignInClientName is the name of the application a hosted sign-in is for.
-- name: SignInClientName :one
SELECT name FROM auth.oidc_clients WHERE client_id = @client_id;

-- ── Account and organization standing (accountstatus.go, signinaudit.go) ────

-- name: AccountStanding :one
-- The account's status and whether it is deleted, for a sign-in to refuse.
SELECT status, (deleted_at IS NOT NULL)::bool AS deleted FROM account.users WHERE id = @user_id;

-- name: OrganizationActive :one
SELECT (status = 'active' AND deleted_at IS NULL)::bool AS active FROM organization.organizations WHERE id = @organization_id;

-- name: HomeOrganization :one
-- The account's own organization (NULL: none).
SELECT organization_id FROM account.users WHERE id = @user_id;

-- name: AccountEmail :one
SELECT email FROM account.users WHERE id = @user_id;

-- ── Forgetting credentials (credentials.go) ──────────────────────────────────

-- name: ForgetPasskeys :execrows
DELETE FROM auth.passkey_credentials WHERE user_id = @user_id;

-- name: ForgetPasskeyCeremonies :execrows
DELETE FROM auth.webauthn_sessions WHERE user_id = @user_id::uuid;

-- name: ForgetTOTP :execrows
DELETE FROM auth.mfa_totp WHERE user_id = @user_id;

-- name: ForgetRecoveryCodes :execrows
DELETE FROM auth.mfa_recovery_codes WHERE user_id = @user_id;

-- name: ForgetOTPFactors :execrows
DELETE FROM auth.mfa_otp_factors WHERE user_id = @user_id;

-- name: ForgetPushDevices :execrows
DELETE FROM auth.mfa_push_devices WHERE user_id = @user_id;

-- name: ForgetPushChallenges :execrows
DELETE FROM auth.mfa_push_challenges WHERE user_id = @user_id AND status = 'pending';

-- name: ForgetPushPairings :execrows
DELETE FROM auth.mfa_push_pairings WHERE user_id = @user_id AND used_at IS NULL;

-- name: ForgetStepUps :execrows
DELETE FROM auth.mfa_verifications WHERE user_id = @user_id;

-- name: ForgetEmailVerifications :execrows
DELETE FROM account.email_verifications WHERE user_id = @user_id;

-- name: ForgetPhoneVerifications :execrows
DELETE FROM account.phone_verifications WHERE user_id = @user_id;

-- name: ForgetLinkedAccounts :execrows
DELETE FROM account.external_identities WHERE user_id = @user_id;

-- name: ForgetConsoleSignIns :execrows
DELETE FROM auth.platform_social_identities WHERE user_id = @user_id;

-- name: ForgetConsoleLinkCodes :execrows
DELETE FROM auth.platform_social_link_codes WHERE user_id = @user_id;

-- name: ForgetSignInCodes :execrows
DELETE FROM auth.login_codes WHERE user_id = @user_id;

-- name: ForgetAPIKeys :execrows
-- Revokes the account's personal API keys.
UPDATE auth.api_keys SET revoked_at = NOW() WHERE user_id = @user_id::uuid AND revoked_at IS NULL;

-- name: ForgetPassword :execrows
DELETE FROM auth.password_credentials WHERE user_id = @user_id;

-- ── Sessions (issue.go, sessions.go, sessionlimit.go, switch.go) ─────────────

-- name: InsertSession :one
-- Opens a session bounded by its organization's maximum age and idle timeout,
-- else by @max_age_s and @idle_s, and never past @not_after (NULL: no bound).
-- An empty @ip, @country, @second_factor or @city is recorded as NULL.
INSERT INTO auth.sessions (id, user_id, organization_id, ip, user_agent, hook_claims, expires_at, idle_timeout, country,
                           second_factor, city)
SELECT @id, @user_id, sqlc.narg('organization_id'), NULLIF(@ip::text, '')::inet, @user_agent, @hook_claims,
       LEAST(NOW() + COALESCE(sp.session_max_age, make_interval(secs => @max_age_s::float8)),
             COALESCE(sqlc.narg('not_after')::timestamptz, 'infinity'::timestamptz)),
       COALESCE(sp.session_idle_timeout, make_interval(secs => @idle_s::float8)),
       NULLIF(@country::text, ''), NULLIF(@second_factor::text, ''), NULLIF(@city::text, '')
FROM (VALUES (1)) AS one
LEFT JOIN organization.security_policies sp ON sp.organization_id = sqlc.narg('organization_id')
RETURNING expires_at, LEAST(last_seen_at + idle_timeout, expires_at)::timestamptz AS idle_expires_at;

-- name: SessionLimit :one
-- The organization's limit on one person's live sessions (NULL: none) and
-- what a sign-in at it does.
SELECT max_sessions, session_limit_action FROM organization.security_policies WHERE organization_id = @organization_id;

-- name: LiveSessionsByUse :many
-- The person's live sessions in the organization, least recently used first.
SELECT id FROM auth.sessions
WHERE user_id = @user_id AND organization_id = @organization_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
ORDER BY last_seen_at, created_at;

-- name: EvictSessions :exec
UPDATE auth.sessions SET revoked_at = NOW() WHERE id = ANY(@ids::uuid[]) AND revoked_at IS NULL;

-- name: ContinueSession :exec
-- Records on the session that it continues another of the same person's: that
-- one's sign-in time, and the second factor carried from it (empty: keep its
-- own).
UPDATE auth.sessions s SET signed_in_at = f.signed_in_at, second_factor = COALESCE(NULLIF(@factor::text, ''), s.second_factor)
FROM auth.sessions f
WHERE s.id = @session_id AND f.id = @from_session_id AND f.user_id = s.user_id;

-- name: SessionCursorTime :one
-- When the person's session that a list cursor names was opened.
SELECT sess.created_at
FROM auth.sessions sess
JOIN account.users u ON u.id = sess.user_id
WHERE sess.id = @id AND sess.user_id = @user_id AND u.deleted_at IS NULL;

-- name: ListUserSessions :many
-- A page of the person's sessions, newest first, before the session at
-- (@before_ts, @before_id) when @after is set; ip is '' when none was
-- recorded. A soft-deleted account's sessions are kept for the record but
-- never listed, nor a superseded one.
SELECT sess.id, sess.user_id, sess.organization_id, COALESCE(host(sess.ip), '')::text AS ip, sess.user_agent,
       sess.created_at, sess.last_seen_at, sess.revoked_at,
       sess.expires_at, ends.idle::timestamptz AS idle_expires_at,
       (CASE WHEN ends.idle <= COALESCE(sess.revoked_at, NOW()) THEN 'expired'
             WHEN sess.revoked_at IS NOT NULL THEN 'revoked'
             ELSE 'active' END)::text AS status,
       COALESCE(sess.country, '')::text AS country, COALESCE(sess.city, '')::text AS city
FROM auth.sessions sess
CROSS JOIN LATERAL (SELECT LEAST(sess.last_seen_at + sess.idle_timeout, sess.expires_at) AS idle) ends
JOIN account.users u ON u.id = sess.user_id
WHERE sess.user_id = @user_id AND u.deleted_at IS NULL AND sess.superseded_by IS NULL
  AND (@after::boolean = FALSE OR (sess.created_at, sess.id) < (@before_ts::timestamptz, @before_id::uuid))
ORDER BY sess.created_at DESC, sess.id DESC
LIMIT @lim;

-- name: CountUserSessions :one
SELECT count(*) FROM auth.sessions sess
JOIN account.users u ON u.id = sess.user_id
WHERE sess.user_id = @user_id AND u.deleted_at IS NULL AND sess.superseded_by IS NULL;

-- name: LoginSessionBounds :one
-- The maximum age and idle timeout, in seconds, of the account's
-- organization's sessions.
SELECT EXTRACT(EPOCH FROM sp.session_max_age)::bigint AS max_age_s, EXTRACT(EPOCH FROM sp.session_idle_timeout)::bigint AS idle_s
FROM account.users u
JOIN organization.security_policies sp ON sp.organization_id = u.organization_id
WHERE u.id = @user_id;

-- ── Sign-up and password (signup.go, password.go, lockout.go) ────────────────

-- name: InsertSignupUser :one
INSERT INTO account.users (organization_id, email, display_name)
VALUES (sqlc.narg('organization_id'), @email, sqlc.narg('display_name'))
RETURNING id, created_at, updated_at;

-- name: LockAccount :one
SELECT id FROM account.users WHERE id = @user_id FOR UPDATE;

-- name: PasswordHash :one
SELECT password_hash FROM auth.password_credentials WHERE user_id = @user_id;

-- name: SetPassword :exec
INSERT INTO auth.password_credentials (user_id, password_hash)
VALUES (@user_id, @password_hash)
ON CONFLICT (user_id) DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = NOW();

-- name: FoldAddress :one
-- An address as the database's LOWER folds it, as the account lookup does.
SELECT LOWER(@address::text)::text;

-- ── Refresh (refresh.go, refreshretry.go) ────────────────────────────────────

-- name: LockRefreshToken :one
-- The refresh token with this hash, its session, account and organization,
-- locked with its session. Whether the session had reached its maximum age or
-- idle timeout by the time it ended (now, if it has not) is decided on the
-- database's clock, as the bounds were set.
SELECT rt.id, rt.session_id, rt.used_at, rt.expires_at,
       s.revoked_at AS session_revoked_at, s.user_id, s.organization_id, u.status AS user_status,
       u.deleted_at AS user_deleted_at, s.hook_claims, s.expires_at AS session_expires_at,
       (s.expires_at <= COALESCE(s.revoked_at, NOW()))::bool AS past_max_age,
       (s.last_seen_at + s.idle_timeout <= COALESCE(s.revoked_at, NOW()))::bool AS past_idle,
       (s.organization_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL))::bool AS organization_active
FROM auth.refresh_tokens rt
JOIN auth.sessions s ON s.id = rt.session_id
JOIN account.users u ON u.id = s.user_id
LEFT JOIN organization.organizations t ON t.id = s.organization_id
WHERE rt.token_hash = @token_hash
FOR UPDATE OF rt, s;

-- name: KeepRotation :exec
-- Keeps, sealed, the pair the rotation of the refresh token issued.
UPDATE auth.refresh_tokens SET replacement_enc = @replacement_enc, replacement_nonce = @replacement_nonce WHERE id = @id;

-- name: KeptRotation :one
-- The sealed pair the rotation of the refresh token issued, its refresh
-- token's hash and the seconds since the rotation: only within @grace_s of it,
-- and while that refresh token is unused and live.
SELECT r.replacement_enc, r.replacement_nonce, n.token_hash, EXTRACT(EPOCH FROM NOW() - r.used_at)::float8 AS seconds
FROM auth.refresh_tokens r
JOIN auth.refresh_tokens n ON n.id = r.replaced_by
WHERE r.id = @id AND r.session_id = @session_id AND r.replacement_enc IS NOT NULL
  AND r.used_at > NOW() - make_interval(secs => @grace_s::float8)
  AND n.used_at IS NULL AND n.expires_at > NOW();

-- name: ClearRefreshRetries :execrows
-- Drops the sealed pairs of rotations made before @cutoff.
UPDATE auth.refresh_tokens SET replacement_enc = NULL, replacement_nonce = NULL
WHERE replacement_enc IS NOT NULL AND used_at < @cutoff;

-- ── Second-factor sign-in challenges (mfachallenge.go, mfalogin.go, mfapolicy.go, risksignin.go) ──

-- name: InsertMFAChallenge :one
INSERT INTO auth.mfa_login_challenges (user_id, organization_id, expires_at, claims, enrollment, first_factor)
VALUES (@user_id, sqlc.narg('organization_id'), @expires_at, @claims, @enrollment, @first_factor)
RETURNING id;

-- name: InsertRiskEmailChallenge :one
-- A challenge met by a code to the account's verified email.
INSERT INTO auth.mfa_login_challenges (user_id, organization_id, expires_at, claims, first_factor, risk_email)
VALUES (@user_id, sqlc.narg('organization_id'), @expires_at, @claims, @first_factor, TRUE)
RETURNING id;

-- name: LockMFAChallenge :one
-- The challenge a sign-in's second step names, locked.
SELECT user_id, organization_id, enrollment, expires_at, passkey_session_id, push_challenge_id, codes_sent,
       risk_email, email_code_sent_at, email_code_hash, email_code_expires_at
FROM auth.mfa_login_challenges WHERE id = @id FOR UPDATE;

-- name: LockMFAChallengeForProof :one
-- LockMFAChallenge with what checking its proof needs.
SELECT user_id, organization_id, expires_at, claims, failed_attempts, passkey_session_id, push_challenge_id,
       enrollment, enrollment_started, first_factor, risk_email, email_code_hash, email_code_expires_at
FROM auth.mfa_login_challenges WHERE id = @id FOR UPDATE;

-- name: CountMFAChallengeFailure :exec
UPDATE auth.mfa_login_challenges SET failed_attempts = @failed_attempts WHERE id = @id;

-- name: CountMFACodeSent :exec
UPDATE auth.mfa_login_challenges SET codes_sent = codes_sent + 1 WHERE id = @id;

-- name: UncountMFACodeSent :exec
UPDATE auth.mfa_login_challenges SET codes_sent = codes_sent - 1 WHERE id = @id;

-- name: SetMFAChallengePasskeySession :execrows
UPDATE auth.mfa_login_challenges SET passkey_session_id = @passkey_session_id WHERE id = @id;

-- name: SetMFAChallengePush :execrows
UPDATE auth.mfa_login_challenges SET push_challenge_id = @push_challenge_id WHERE id = @id;

-- name: StartMFAChallengeEnrollment :exec
UPDATE auth.mfa_login_challenges SET enrollment_started = TRUE WHERE id = @id;

-- name: IssueRiskEmailCode :exec
-- Replaces a risk challenge's emailed code, counting the send.
UPDATE auth.mfa_login_challenges
SET email_code_hash = @email_code_hash, email_code_expires_at = @email_code_expires_at, email_code_sent_at = NOW(),
    codes_sent = codes_sent + 1
WHERE id = @id;

-- name: WithdrawRiskEmailCode :exec
-- Puts back a risk challenge's earlier code, pacing and count when the code
-- @sent_hash names did not go.
UPDATE auth.mfa_login_challenges
SET email_code_hash = sqlc.narg('email_code_hash'), email_code_expires_at = sqlc.narg('email_code_expires_at'),
    email_code_sent_at = sqlc.narg('email_code_sent_at'), codes_sent = codes_sent - 1
WHERE id = @id AND email_code_hash = @sent_hash;

-- name: AccountEmailVerified :one
-- The account's email and whether it is verified.
SELECT email, (email_verified_at IS NOT NULL)::bool AS verified FROM account.users WHERE id = @user_id;

-- name: VerifiedAccountEmail :one
-- The account's email, when it is verified.
SELECT email FROM account.users WHERE id = @user_id AND email_verified_at IS NOT NULL;

-- name: EnsureLoginAttemptBudget :exec
INSERT INTO auth.mfa_attempt_budgets (user_id, purpose) VALUES (@user_id, 'login')
ON CONFLICT DO NOTHING;

-- name: LockLoginAttemptBudget :one
SELECT failed_attempts, window_started_at, locked_until
FROM auth.mfa_attempt_budgets WHERE user_id = @user_id AND purpose = 'login'
FOR UPDATE;

-- name: SetLoginAttemptBudget :exec
UPDATE auth.mfa_attempt_budgets
SET failed_attempts = @failed_attempts, window_started_at = @window_started_at, locked_until = sqlc.narg('locked_until')
WHERE user_id = @user_id AND purpose = 'login';

-- name: ClearLoginAttemptBudget :exec
DELETE FROM auth.mfa_attempt_budgets WHERE user_id = @user_id AND purpose = 'login';

-- ── Trusted devices (trusteddevice.go) ───────────────────────────────────────

-- name: InsertTrustedDevice :one
INSERT INTO auth.trusted_devices (user_id, organization_id, token_hash, label, expires_at)
VALUES (@user_id, sqlc.narg('organization_id'), @token_hash, @label, @expires_at)
RETURNING id;

-- name: ListTrustedDevices :many
-- The person's live remembered devices, newest first: in every organization
-- when @organization_id is NULL, else only in it; current marks the one with
-- @current_hash.
SELECT id, organization_id, label, created_at, last_used_at, expires_at, (token_hash = @current_hash::text)::bool AS current
FROM auth.trusted_devices
WHERE user_id = @user_id AND (sqlc.narg('organization_id')::uuid IS NULL OR organization_id = sqlc.narg('organization_id'))
  AND expires_at > NOW()
ORDER BY created_at DESC, id;

-- name: ForgetTrustedDevices :many
-- Forgets the person's remembered devices: in every organization when
-- @organization_id is NULL, else only in it; all of them, or with @device_id
-- only that one.
DELETE FROM auth.trusted_devices
WHERE user_id = @user_id AND (sqlc.narg('organization_id')::uuid IS NULL OR organization_id = sqlc.narg('organization_id'))
  AND (sqlc.narg('device_id')::uuid IS NULL OR id = sqlc.narg('device_id'))
RETURNING id, organization_id;

-- name: CountTrustedDevices :one
SELECT count(*)::int AS devices, count(DISTINCT user_id)::int AS users
FROM auth.trusted_devices
WHERE organization_id = @organization_id AND expires_at > NOW();

-- name: IsHomeMember :one
-- Whether the organization is the account's home.
SELECT EXISTS (SELECT 1 FROM account.users WHERE id = @user_id AND organization_id = @organization_id AND deleted_at IS NULL)::bool;
