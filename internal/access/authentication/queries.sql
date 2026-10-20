-- Queries for the authentication domain.
-- Static queries with fully-typed, non-nullable parameters are converted.
-- Queries involving nullable UUID columns passed as Go interface{}/nil
-- (sessions.tenant_id, mfa_login_challenges.tenant_id, trusted_devices.tenant_id)
-- remain hand-written because they require Go-nil → SQL NULL semantics that
-- sqlc's uuid override cannot express without additional NULLIF wrappers that
-- would silently treat the zero UUID as NULL.
-- The Refresh join (FOR UPDATE OF rt across three tables) is also left raw.

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

-- name: GetClientTenant :one
-- The tenant an OAuth client belongs to (whose policy a hosted sign-in for it
-- is held to).
SELECT tenant_id FROM auth.oidc_clients WHERE client_id = @client_id;

-- name: InsertLoginSession :exec
INSERT INTO auth.login_sessions (token_hash, user_id, expires_at, ip, user_agent)
VALUES (@token_hash, @user_id, @expires_at, NULLIF(@ip::text, '')::inet, @user_agent);

-- name: GetLoginSession :one
SELECT id, user_id, expires_at, created_at FROM auth.login_sessions WHERE token_hash = @token_hash;

-- name: GetLoginSessionUser :one
-- The user behind a live hosted-login session, and their own organization (NULL
-- for a user without one), and when the sign-in happened. No row when the
-- session is unknown or expired, or the user or their organization is no
-- longer active.
SELECT s.user_id, u.tenant_id, s.created_at
FROM auth.login_sessions s
JOIN "user".users u ON u.id = s.user_id
LEFT JOIN tenant.tenants t ON t.id = u.tenant_id
WHERE s.token_hash = @token_hash
  AND s.expires_at > NOW()
  AND u.status = 'active' AND u.deleted_at IS NULL
  AND (u.tenant_id IS NULL OR (t.status = 'active' AND t.deleted_at IS NULL));

-- EndLoginSession ends the hosted-login (browser) session behind a cookie —
-- expired or not, since what it started can outlive it — and returns its id,
-- its user and that user's own organization (NULL for none), so the sign-out
-- can end what the session started and record it. No row: nothing to end.
-- name: EndLoginSession :one
WITH ended AS (
    DELETE FROM auth.login_sessions WHERE token_hash = @token_hash
    RETURNING id, user_id
)
SELECT ended.id, ended.user_id, u.tenant_id
FROM ended LEFT JOIN "user".users u ON u.id = ended.user_id;

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
-- the organisation that remembered it, and returns its id; no row otherwise.
UPDATE auth.trusted_devices SET last_used_at = NOW()
WHERE token_hash = @token_hash AND user_id = @user_id AND tenant_id = @tenant_id AND expires_at > NOW()
RETURNING id;

-- PurgeExpiredTrustedDevices deletes remembered devices that expired before
-- the cutoff; they no longer skip anything.
-- name: PurgeExpiredTrustedDevices :execrows
DELETE FROM auth.trusted_devices WHERE expires_at < @cutoff;

-- name: CheckTenantMembership :one
SELECT EXISTS (
    SELECT 1 FROM rbac.user_roles membership
    JOIN rbac.roles role ON role.id = membership.role_id AND role.tenant_id = membership.tenant_id
    JOIN tenant.tenants organization ON organization.id = membership.tenant_id
    JOIN "user".users account ON account.id = membership.user_id
    WHERE membership.user_id = @user_id AND membership.tenant_id = @tenant_id
      AND organization.status = 'active' AND organization.deleted_at IS NULL
      AND account.status = 'active' AND account.deleted_at IS NULL
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
RETURNING id, tenant_id;

-- SupersedeSession ends the session a switch of organisation was made from —
-- only while it is live (not revoked, not past its maximum age or idle timeout)
-- and the caller's own — and records the session that replaced it. Ending it
-- is what stops its refresh tokens. Returns the organization it belonged to
-- (NULL for none). No row: it had already ended.
-- name: SupersedeSession :one
UPDATE auth.sessions SET revoked_at = NOW(), superseded_by = @new_session_id
WHERE id = @session_id AND user_id = @user_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
RETURNING tenant_id;

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
SELECT id FROM "user".users WHERE id = @user_id FOR NO KEY UPDATE;

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
RETURNING id, tenant_id;

-- EndLoginSessionsForUser ends every hosted-login (browser) session of the
-- user — the way hosted sign-out ends one, by deleting it — and returns how
-- many of them had not yet expired.
-- name: EndLoginSessionsForUser :one
WITH ended AS (
    DELETE FROM auth.login_sessions WHERE user_id = @user_id
    RETURNING expires_at
)
SELECT COUNT(*) FILTER (WHERE expires_at > NOW())::bigint AS live
FROM ended;

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
-- Revokes a session scoped to its owner and returns the (nullable) tenant for
-- event emission. No row (pgx.ErrNoRows) means the session isn't the caller's
-- or has already ended (revoked, or past its maximum age or idle timeout) — a
-- safe no-op, never a cross-user takedown.
UPDATE auth.sessions SET revoked_at = NOW()
WHERE id = @session_id AND user_id = @user_id AND revoked_at IS NULL
  AND expires_at > NOW() AND last_seen_at + idle_timeout > NOW()
RETURNING tenant_id;

-- name: InsertPasswordCredential :exec
-- Stores the Argon2id hash for a newly created identity (signup / hosted register).
INSERT INTO auth.password_credentials (user_id, password_hash)
VALUES (@user_id, @password_hash);

-- name: InsertTenantlessUser :one
-- Tenant-less signup: creates the identity with tenant_id NULL (a literal, not a
-- bind — membership lives in rbac.user_roles). display_name is nullable text.
INSERT INTO "user".users (tenant_id, email, display_name)
VALUES (NULL, @email, @display_name)
RETURNING id, created_at, updated_at;

-- name: InsertTenantlessSession :one
-- Tenant-less session: tenant_id is a literal NULL (not a bind). ip goes through
-- NULLIF so an empty string stores as SQL NULL, matching InsertLoginSession.
-- With no organisation, the platform's session bounds apply. Returns when it
-- ends however active, and when it ends unless renewed.
INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent, expires_at, idle_timeout, country)
VALUES (@id, @user_id, NULL, NULLIF(@ip::text, '')::inet, @user_agent,
        NOW() + make_interval(secs => @max_age_seconds::float8),
        make_interval(secs => @idle_seconds::float8),
        NULLIF(@country::text, ''))
RETURNING expires_at, LEAST(last_seen_at + idle_timeout, expires_at)::timestamptz AS idle_expires_at;

-- name: DeleteMFALoginChallenge :exec
DELETE FROM auth.mfa_login_challenges WHERE id = @id;

-- PurgeEndedSessions deletes API and console sessions past retention: ended
-- (revoked) before the cutoff, or never ended but past its maximum age or idle
-- timeout before the cutoff, or with every refresh token expired before it
-- (none was usable after it). A session opened after the cutoff is always kept.
-- Their refresh tokens go with them (cascade). Returns what it deleted;
-- expired marks the sessions that were never ended, which are announced as
-- expired.
-- name: PurgeEndedSessions :many
DELETE FROM auth.sessions s
WHERE s.created_at < @cutoff
  AND (
      (s.revoked_at IS NOT NULL AND s.revoked_at < @cutoff)
      OR (s.revoked_at IS NULL AND (
          s.expires_at < @cutoff
          OR s.last_seen_at + s.idle_timeout < @cutoff
          OR NOT EXISTS (
              SELECT 1 FROM auth.refresh_tokens rt
              WHERE rt.session_id = s.id AND rt.expires_at >= @cutoff)))
  )
RETURNING s.id, s.user_id, s.tenant_id, (s.revoked_at IS NULL)::boolean AS expired;

-- PurgeExpiredCeremonies deletes passkey ceremony state that has expired
-- unfinished — every sign-in page now starts one in the background, and most
-- are never completed. An expired ceremony can no longer be finished.
-- name: PurgeExpiredCeremonies :execrows
DELETE FROM auth.webauthn_sessions WHERE expires_at < NOW();

-- PurgeExpiredLoginSessions deletes hosted-login sessions that expired before
-- the cutoff. Their cookie stopped being sent when they expired.
-- name: PurgeExpiredLoginSessions :execrows
DELETE FROM auth.login_sessions WHERE expires_at < @cutoff;

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
-- factor to sign in to an organisation: the account's own flag, the
-- organisation's requirement and grace period, and whether the account is an
-- administrator there — holds a role, directly or through a group, granting
-- any write permission.
-- name: MFARequirement :one
SELECT u.mfa_required,
       u.created_at,
       COALESCE(sp.mfa_enforcement, 'optional')::text AS enforcement,
       COALESCE(sp.mfa_grace_days, 0)::int AS grace_days,
       sp.mfa_enforced_since,
       EXISTS (
           SELECT 1
           FROM rbac.user_roles ur
           JOIN rbac.role_permissions rp ON rp.role_id = ur.role_id
           JOIN rbac.permissions p ON p.id = rp.permission_id
           WHERE ur.user_id = u.id AND ur.tenant_id = @tenant_id AND p.key LIKE '%.write'
           UNION ALL
           SELECT 1
           FROM tenant.group_members gm
           JOIN rbac.group_roles gr ON gr.group_id = gm.group_id AND gr.tenant_id = gm.tenant_id
           JOIN rbac.role_permissions rp ON rp.role_id = gr.role_id
           JOIN rbac.permissions p ON p.id = rp.permission_id
           WHERE gm.user_id = u.id AND gm.tenant_id = @tenant_id AND p.key LIKE '%.write'
       ) AS is_admin
FROM "user".users u
LEFT JOIN tenant.security_policies sp ON sp.tenant_id = @tenant_id
WHERE u.id = @user_id;
