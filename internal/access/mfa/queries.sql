-- Queries for the access/mfa domain.
-- All static queries are compiled by sqlc into ./dbgen.

-- name: ConfirmMFATOTP :exec
UPDATE auth.mfa_totp SET confirmed_at = NOW() WHERE user_id = $1;

-- name: DeleteMFATOTP :exec
DELETE FROM auth.mfa_totp WHERE user_id = $1;

-- GetMFATOTPConfirmed returns confirmed_at: nil while the app is unconfirmed.

-- name: GetMFATOTPConfirmed :one
SELECT confirmed_at FROM auth.mfa_totp WHERE user_id = $1;

-- name: DeleteMFARecoveryCodes :exec
DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1;

-- name: InsertMFARecoveryCode :exec
INSERT INTO auth.mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2);

-- name: GetMFARecoveryCodeStats :one
SELECT
    count(*)                             AS total,
    count(*) FILTER (WHERE used_at IS NULL) AS remaining
FROM auth.mfa_recovery_codes WHERE user_id = $1;

-- name: ListUnusedRecoveryCodes :many
SELECT id, code_hash FROM auth.mfa_recovery_codes
WHERE user_id = $1 AND used_at IS NULL
FOR UPDATE;

-- name: MarkRecoveryCodeUsed :execrows
-- Spends a recovery code: one row only for the first of two concurrent uses.
UPDATE auth.mfa_recovery_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL;

-- RecordStepUp records that a session proved a second factor. Only a live
-- session of the user's own is recorded; for any other nothing is written.
-- name: RecordStepUp :exec
INSERT INTO auth.mfa_verifications (session_id, user_id, method, verified_at)
SELECT s.id, s.user_id, @method::text, NOW()
FROM auth.sessions s
WHERE s.id = @session_id AND s.user_id = @user_id AND s.revoked_at IS NULL
  AND s.expires_at > NOW() AND s.last_seen_at + s.idle_timeout > NOW()
ON CONFLICT (session_id) DO UPDATE SET method = EXCLUDED.method, verified_at = NOW();

-- StepUpState is a session's step-up as its organization judges it: fresh
-- while inside the organization's window, and counted only when met by a
-- factor type the organization accepts (step_up_methods NULL: any). A session
-- that has ended reads as never stepped up.
-- name: StepUpState :one
SELECT v.verified_at, v.method,
       COALESCE(v.verified_at > NOW() - COALESCE(sp.step_up_window, INTERVAL '5 minutes'), FALSE)::bool AS fresh,
       COALESCE(sp.step_up_methods IS NULL OR v.method = ANY (sp.step_up_methods), FALSE)::bool AS method_counts,
       EXTRACT(EPOCH FROM COALESCE(sp.step_up_window, INTERVAL '5 minutes'))::bigint AS window_seconds,
       sp.step_up_methods
FROM (SELECT @session_id::uuid AS id, @user_id::uuid AS user_id) q
LEFT JOIN auth.sessions s ON s.id = q.id AND s.user_id = q.user_id AND s.revoked_at IS NULL
  AND s.expires_at > NOW() AND s.last_seen_at + s.idle_timeout > NOW()
LEFT JOIN auth.mfa_verifications v ON v.session_id = s.id
LEFT JOIN organization.security_policies sp ON sp.organization_id = s.organization_id;

-- StepUpFactorsHeld says which kinds of factor the user could step up with —
-- a confirmed authenticator app (or its recovery codes), a confirmed email or
-- SMS factor, a passkey while the organization allows passkeys — and which
-- factor types the organization counts (NULL: every one).
-- name: StepUpFactorsHeld :one
SELECT
    EXISTS (SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = @user_id AND t.confirmed_at IS NOT NULL)::bool AS totp,
    EXISTS (SELECT 1 FROM auth.mfa_otp_factors f WHERE f.user_id = @user_id AND f.verified_at IS NOT NULL)::bool AS otp,
    (EXISTS (SELECT 1 FROM auth.passkey_credentials c WHERE c.user_id = @user_id)
     AND COALESCE((SELECT ap.passkey_enabled FROM organization.auth_policy ap WHERE ap.organization_id = @organization_id::uuid), TRUE))::bool AS passkeys,
    EXISTS (SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = @user_id)::bool AS push,
    (SELECT sp.step_up_methods FROM organization.security_policies sp WHERE sp.organization_id = @organization_id::uuid)::text[] AS step_up_methods;

-- OrgStepUpPolicy is how long a step-up lasts in an organization and whether
-- it counts every factor type (no organization, or none set: 5 minutes, yes).
-- SessionSignedInRecently says whether the user's live session continues a
-- sign-in made within its organization's step-up window, and that window.
-- name: SessionSignedInRecently :one
SELECT COALESCE(s.signed_in_at > NOW() - COALESCE(sp.step_up_window, INTERVAL '5 minutes'), FALSE)::bool AS recent,
       EXTRACT(EPOCH FROM COALESCE(sp.step_up_window, INTERVAL '5 minutes'))::bigint AS window_seconds
FROM (SELECT @session_id::uuid AS id, @user_id::uuid AS user_id) q
LEFT JOIN auth.sessions s ON s.id = q.id AND s.user_id = q.user_id AND s.revoked_at IS NULL
  AND s.expires_at > NOW() AND s.last_seen_at + s.idle_timeout > NOW()
LEFT JOIN organization.security_policies sp ON sp.organization_id = s.organization_id;

-- name: OrgStepUpPolicy :one
SELECT EXTRACT(EPOCH FROM COALESCE(sp.step_up_window, INTERVAL '5 minutes'))::bigint AS window_seconds,
       (sp.step_up_methods IS NULL)::bool AS every_factor
FROM (SELECT @organization_id::uuid AS id) q
LEFT JOIN organization.security_policies sp ON sp.organization_id = q.id;


-- name: DeleteMFAOTPFactors :exec
DELETE FROM auth.mfa_otp_factors WHERE user_id = $1;

-- name: InsertMFAOTPCode :exec
INSERT INTO auth.mfa_otp_codes (factor_id, code_hash, expires_at, purpose)
VALUES (@factor_id, @code_hash, @expires_at, @purpose);

-- UpsertMFAOTPFactor adds an email or SMS factor, or returns the one already
-- held for that address or number untouched: asking for a new code to an
-- address already confirmed must not take the factor away until it is.
-- name: UpsertMFAOTPFactor :one
INSERT INTO auth.mfa_otp_factors (user_id, channel, destination)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, channel, destination) DO UPDATE SET destination = EXCLUDED.destination
RETURNING id;

-- GetOTPCodeForConfirm fetches a single pending OTP code for the EnrollOTPConfirm path.

-- name: GetOTPCodeForConfirm :one
SELECT c.id
FROM auth.mfa_otp_codes c
JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
WHERE f.id = $1 AND f.user_id = $2 AND c.code_hash = $3 AND c.purpose = 'enrollment'
  AND c.used_at IS NULL AND c.expires_at > NOW()
ORDER BY c.created_at DESC LIMIT 1
FOR UPDATE;

-- name: MarkOTPCodeUsed :execrows
-- Spends an email or SMS code: one row only for the first of two concurrent
-- uses.
UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1 AND used_at IS NULL;

-- name: MarkOTPFactorVerified :exec
UPDATE auth.mfa_otp_factors SET verified_at = NOW() WHERE id = $1;

-- name: ListOTPFactors :many
SELECT id, user_id, channel, destination, verified_at, created_at
FROM auth.mfa_otp_factors WHERE user_id = $1 ORDER BY created_at;

-- name: DeleteOTPFactor :execrows
DELETE FROM auth.mfa_otp_factors WHERE id = $1 AND user_id = $2;

-- name: GetOTPFactorForChallenge :one
SELECT channel, destination, verified_at
FROM auth.mfa_otp_factors WHERE id = $1 AND user_id = $2;

-- GetOTPCodeForVerify finds a pending OTP code for any verified factor of the user.

-- ── Push MFA ──────────────────────────────────────────────────────────────────

-- name: ListPushDevices :many
SELECT id, user_id, name, platform, created_at, last_seen_at
FROM auth.mfa_push_devices WHERE user_id = $1 ORDER BY created_at;

-- DeletePushDeviceByCredential removes a linked phone that proves it is that
-- device with its own credential.
-- name: DeletePushDeviceByCredential :execrows
DELETE FROM auth.mfa_push_devices WHERE id = @id AND user_id = @user_id AND device_token_hash = @device_token_hash;

-- IsOrganizationMember says whether the user belongs to the organization: holds a
-- role in it, or has it as their home organization.
-- name: IsOrganizationMember :one
SELECT (EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = @user_id AND ur.organization_id = @organization_id)
     OR EXISTS (SELECT 1 FROM account.users u WHERE u.id = @user_id AND u.organization_id = @organization_id AND u.deleted_at IS NULL))::bool;

-- name: DeletePushDevice :execrows
DELETE FROM auth.mfa_push_devices WHERE id = $1 AND user_id = $2;

-- name: InsertPushChallenge :one
INSERT INTO auth.mfa_push_challenges (user_id, action, context, match_number)
VALUES (@user_id, @action, @context, @match_number)
RETURNING id, user_id, action, context, status, expires_at, created_at;

-- RecentPushChallenges counts the user's push requests of the last ten
-- minutes, and those denied in the last hour.
-- name: RecentPushChallenges :one
SELECT count(*) FILTER (WHERE created_at > NOW() - INTERVAL '10 minutes')::int AS sent,
       count(*) FILTER (WHERE status = 'denied')::int AS denied
FROM auth.mfa_push_challenges
WHERE user_id = @user_id AND created_at > NOW() - INTERVAL '1 hour';

-- name: GetPushChallenge :one
SELECT id, user_id, action, context, status, expires_at, created_at
FROM auth.mfa_push_challenges WHERE id = $1;

-- name: GetPushChallengeForUpdate :one
SELECT id, user_id, status, expires_at, match_number
FROM auth.mfa_push_challenges WHERE id = $1
FOR UPDATE;

-- ExpirePushChallenge records that a pending push request has passed its
-- expiry, so every reader sees it as expired.
-- name: ExpirePushChallenge :exec
UPDATE auth.mfa_push_challenges SET status = 'expired'
WHERE id = $1 AND status = 'pending' AND expires_at <= NOW();

-- name: UpdatePushChallengeStatus :exec
UPDATE auth.mfa_push_challenges
SET status = $2, responded_at = NOW()
WHERE id = $1;

-- GetOTPCodeForVerify finds a live code of the user's sent for purpose
-- (sign_in or step_up), so one sent for the other never counts.
-- name: GetOTPCodeForVerify :one
SELECT c.id
FROM auth.mfa_otp_codes c
JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
WHERE f.user_id = @user_id AND f.verified_at IS NOT NULL AND c.code_hash = @code_hash
  AND c.purpose = @purpose AND c.used_at IS NULL AND c.expires_at > NOW()
ORDER BY c.created_at DESC LIMIT 1
FOR UPDATE;

-- LoginFactorCounts says which second factors the user can meet a sign-in
-- challenge with: a confirmed authenticator app, unused recovery codes,
-- passkeys (while the user's organization allows passkeys) and push devices.
-- name: LoginFactorCounts :one
SELECT
    EXISTS (SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = @user_id AND t.confirmed_at IS NOT NULL) AS totp,
    (SELECT count(*) FROM auth.mfa_recovery_codes r WHERE r.user_id = @user_id AND r.used_at IS NULL)::int AS recovery_codes,
    CASE WHEN COALESCE((SELECT ap.passkey_enabled FROM account.users u
                        JOIN organization.auth_policy ap ON ap.organization_id = u.organization_id
                        WHERE u.id = @user_id), TRUE)
         THEN (SELECT count(*) FROM auth.passkey_credentials p WHERE p.user_id = @user_id)
         ELSE 0 END::int AS passkeys,
    (SELECT count(*) FROM auth.mfa_push_devices d
      WHERE d.user_id = @user_id AND d.device_token_expires_at > NOW())::int AS push_devices;

-- PushChallengeForLogin reads a push challenge of the user's for a sign-in,
-- locked, to see whether it has been approved.
-- name: PushChallengeForLogin :one
SELECT status, expires_at FROM auth.mfa_push_challenges
WHERE id = @id AND user_id = @user_id
FOR UPDATE;

-- name: PushChallengeForStepUp :one
-- A step-up push request of the user's, under lock, with the session it was
-- raised for.
SELECT status, expires_at, action, COALESCE(context->>'session_id', '')::text AS session_id
FROM auth.mfa_push_challenges
WHERE id = @id AND user_id = @user_id
FOR UPDATE;

-- name: SpendPushChallenge :exec
DELETE FROM auth.mfa_push_challenges WHERE id = $1;

-- ── Authenticator app (totp.go) ──────────────────────────────────────────────

-- name: ConsumeTOTPStep :execrows
-- Marks a TOTP time step used: no row when that step or a later one already
-- was, so one code never authenticates twice.
UPDATE auth.mfa_totp SET last_used_step = @step
WHERE user_id = @user_id AND (last_used_step IS NULL OR last_used_step < @step);

-- name: LockTOTPConfirmed :one
-- Whether the user's app is confirmed, its row locked for the setup that
-- replaces it.
SELECT (confirmed_at IS NOT NULL)::bool AS confirmed FROM auth.mfa_totp WHERE user_id = @user_id FOR UPDATE;

-- name: StagePendingTOTP :exec
-- Sets up a new app beside the confirmed one, until a code from it confirms it.
UPDATE auth.mfa_totp
SET pending_secret_ct = @pending_secret_ct, pending_secret_nonce = @pending_secret_nonce, pending_started_at = NOW()
WHERE user_id = @user_id;

-- name: StartTOTP :exec
-- Sets up the user's first app, unconfirmed, in place of any unconfirmed one.
INSERT INTO auth.mfa_totp (user_id, secret_ct, secret_nonce)
VALUES (@user_id, @secret_ct, @secret_nonce)
ON CONFLICT (user_id) DO UPDATE SET
    secret_ct = EXCLUDED.secret_ct, secret_nonce = EXCLUDED.secret_nonce,
    confirmed_at = NULL, pending_secret_ct = NULL, pending_secret_nonce = NULL,
    pending_started_at = NULL;

-- name: LockTOTPSetup :one
-- The app being set up beside a confirmed one (pending_*: none when NULL) and
-- whether one is confirmed, locked for the code that confirms it.
SELECT pending_secret_ct, pending_secret_nonce, pending_started_at, (confirmed_at IS NOT NULL)::bool AS confirmed
FROM auth.mfa_totp WHERE user_id = @user_id FOR UPDATE;

-- name: PromotePendingTOTP :exec
-- Makes the app set up beside the confirmed one the user's app, its confirming
-- code's step burned.
UPDATE auth.mfa_totp
SET secret_ct = pending_secret_ct, secret_nonce = pending_secret_nonce,
    confirmed_at = NOW(), last_used_step = @step,
    pending_secret_ct = NULL, pending_secret_nonce = NULL, pending_started_at = NULL
WHERE user_id = @user_id;

-- name: GetTOTPSecret :one
SELECT secret_ct, secret_nonce, confirmed_at FROM auth.mfa_totp WHERE user_id = @user_id;

-- Resetting a person's second factors (ResetForUser), each kind counted.

-- name: ResetTOTP :execrows
DELETE FROM auth.mfa_totp WHERE user_id = @user_id;

-- name: ResetRecoveryCodes :execrows
DELETE FROM auth.mfa_recovery_codes WHERE user_id = @user_id;

-- name: ResetOTPFactors :execrows
DELETE FROM auth.mfa_otp_factors WHERE user_id = @user_id;

-- name: ResetPushDevices :execrows
DELETE FROM auth.mfa_push_devices WHERE user_id = @user_id;

-- name: ResetPendingPushChallenges :execrows
DELETE FROM auth.mfa_push_challenges WHERE user_id = @user_id AND status = 'pending';

-- name: ResetLivePushPairings :execrows
DELETE FROM auth.mfa_push_pairings WHERE user_id = @user_id AND used_at IS NULL AND expires_at > NOW();

-- name: ResetTrustedDevices :execrows
DELETE FROM auth.trusted_devices WHERE user_id = @user_id;

-- name: ResetStepUps :execrows
DELETE FROM auth.mfa_verifications WHERE user_id = @user_id;

-- name: ResetFailureStreaks :execrows
DELETE FROM auth.mfa_failure_streaks WHERE user_id = @user_id;

-- ── Email and SMS codes (otp.go, login.go) ───────────────────────────────────

-- name: LockOTPFactor :exec
-- Holds the factor until the code being sent to it commits, so two sends
-- can't both pass the wait.
SELECT 1 FROM auth.mfa_otp_factors WHERE id = @id FOR UPDATE;

-- name: OTPSendHistory :one
-- When the factor's last code went, and the codes sent in the last hour to
-- the user's factors and to the destination (how many, and the oldest). A
-- time with no code to take it from is the epoch, long enough ago to impose
-- no wait.
SELECT
    COALESCE((SELECT max(c.created_at) FROM auth.mfa_otp_codes c WHERE c.factor_id = @factor_id),
             'epoch')::timestamptz AS factor_last,
    (SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
      WHERE f.user_id = @user_id AND c.created_at > NOW() - INTERVAL '1 hour')::int AS user_hour,
    COALESCE((SELECT min(c.created_at) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
      WHERE f.user_id = @user_id AND c.created_at > NOW() - INTERVAL '1 hour'), 'epoch')::timestamptz AS user_oldest,
    (SELECT count(*) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
      WHERE f.channel = @channel AND f.destination = @destination AND c.created_at > NOW() - INTERVAL '1 hour')::int AS destination_hour,
    COALESCE((SELECT min(c.created_at) FROM auth.mfa_otp_codes c JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
      WHERE f.channel = @channel AND f.destination = @destination AND c.created_at > NOW() - INTERVAL '1 hour'),
             'epoch')::timestamptz AS destination_oldest;

-- name: ExpireLiveOTPCodes :exec
-- Ends the factor's unused codes, so only the newest works.
UPDATE auth.mfa_otp_codes SET expires_at = NOW()
WHERE factor_id = @factor_id AND used_at IS NULL AND expires_at > NOW();

-- name: WithdrawOTPCode :exec
-- Removes a code the provider did not take.
DELETE FROM auth.mfa_otp_codes WHERE factor_id = @factor_id AND code_hash = @code_hash;

-- name: OTPFactorHoldings :one
-- How many email and SMS factors the user holds, and whether one is already
-- for this channel and destination.
SELECT count(*)::int AS held,
       COALESCE(bool_or(channel = @channel AND destination = @destination), FALSE)::bool AS already
FROM auth.mfa_otp_factors WHERE user_id = @user_id;

-- ── Attempt budgets (attempts.go) ────────────────────────────────────────────

-- name: EnsureAttemptBudget :exec
INSERT INTO auth.mfa_attempt_budgets (user_id, purpose) VALUES (@user_id, @purpose)
ON CONFLICT DO NOTHING;

-- name: LockAttemptBudget :one
SELECT failed_attempts, window_started_at, locked_until
FROM auth.mfa_attempt_budgets WHERE user_id = @user_id AND purpose = @purpose
FOR UPDATE;

-- name: SetAttemptBudget :exec
UPDATE auth.mfa_attempt_budgets
SET failed_attempts = @failed_attempts, window_started_at = @window_started_at, locked_until = sqlc.narg('locked_until')
WHERE user_id = @user_id AND purpose = @purpose;

-- name: ClearAttemptBudget :exec
DELETE FROM auth.mfa_attempt_budgets WHERE user_id = @user_id AND purpose = @purpose;

-- name: RefundAttempt :exec
-- Hands back one attempt, lifting the lock it may have set.
UPDATE auth.mfa_attempt_budgets
SET failed_attempts = GREATEST(failed_attempts - 1, 0), locked_until = NULL
WHERE user_id = @user_id AND purpose = @purpose;

-- name: PurgeExpiredPushChallenges :execrows
DELETE FROM auth.mfa_push_challenges WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.mfa_push_challenges c WHERE c.expires_at < @cutoff LIMIT @max_rows));

-- name: PurgeExpiredOTPCodes :execrows
DELETE FROM auth.mfa_otp_codes WHERE ctid = ANY(ARRAY(
    SELECT c.ctid FROM auth.mfa_otp_codes c WHERE c.expires_at < @cutoff LIMIT @max_rows));

-- ── Linked phones (push.go, pushstepup.go) ───────────────────────────────────

-- name: UpsertPushDevice :one
-- Links a phone, or links it again with a new device credential.
INSERT INTO auth.mfa_push_devices
    (user_id, name, push_token_ct, push_token_nonce, push_token_hash,
     platform, device_token_hash, device_token_expires_at)
VALUES (@user_id, @name, @push_token_ct, @push_token_nonce, @push_token_hash,
        @platform, @device_token_hash, NOW() + make_interval(secs => @ttl_seconds::float8))
ON CONFLICT (user_id, push_token_hash) DO UPDATE SET
    name = EXCLUDED.name,
    push_token_ct = EXCLUDED.push_token_ct,
    push_token_nonce = EXCLUDED.push_token_nonce,
    platform = EXCLUDED.platform,
    device_token_hash = EXCLUDED.device_token_hash,
    device_token_expires_at = EXCLUDED.device_token_expires_at,
    last_seen_at = NOW()
RETURNING id, user_id, name, platform, created_at, last_seen_at;

-- name: CloseUndeliveredPushChallenge :exec
-- Closes a pending request no phone accepted.
UPDATE auth.mfa_push_challenges SET status = 'expired', expires_at = LEAST(expires_at, NOW())
WHERE id = @id AND status = 'pending';

-- name: PushDeviceByCredential :one
-- The user's linked phone with this unexpired device credential.
SELECT id FROM auth.mfa_push_devices
WHERE user_id = @user_id AND device_token_hash = @device_token_hash AND device_token_expires_at > NOW();

-- name: ListPushTargets :many
-- The sealed push tokens of the user's phones whose device credential hasn't
-- expired.
SELECT platform, push_token_ct, push_token_nonce, push_token_hash
FROM auth.mfa_push_devices
WHERE user_id = @user_id AND device_token_expires_at > NOW();

-- name: RetirePushToken :exec
-- Expires the device credential of the phone with this push token.
UPDATE auth.mfa_push_devices SET device_token_expires_at = NOW()
WHERE user_id = @user_id AND push_token_hash = @push_token_hash AND device_token_expires_at > NOW();

-- name: LinkedPushDevice :one
-- The user's linked phone, when it presents its unexpired device credential.
SELECT id FROM auth.mfa_push_devices
WHERE id = @id AND user_id = @user_id AND device_token_hash = @device_token_hash AND device_token_expires_at > NOW();

-- name: LockLinkedPushDevice :one
-- LinkedPushDevice, locked for the change it makes.
SELECT id FROM auth.mfa_push_devices
WHERE id = @id AND user_id = @user_id AND device_token_hash = @device_token_hash AND device_token_expires_at > NOW()
FOR UPDATE;

-- name: ListPendingPushChallenges :many
-- The user's requests still waiting for an answer, newest first.
SELECT id, user_id, action, context, status, expires_at, created_at
FROM auth.mfa_push_challenges
WHERE user_id = @user_id AND status = 'pending' AND expires_at > NOW()
ORDER BY created_at DESC
LIMIT @row_limit;

-- name: DeleteOtherPushDevicesWithToken :exec
-- Removes the user's other links holding the same push token.
DELETE FROM auth.mfa_push_devices WHERE user_id = @user_id AND push_token_hash = @push_token_hash AND id <> @id;

-- name: SetPushDeviceToken :exec
UPDATE auth.mfa_push_devices
SET push_token_ct = @push_token_ct, push_token_nonce = @push_token_nonce, push_token_hash = @push_token_hash
WHERE id = @id;

-- name: HasPushDevice :one
SELECT EXISTS (SELECT 1 FROM auth.mfa_push_devices WHERE user_id = @user_id)::bool;

-- ── Pairing codes (pairing.go) ───────────────────────────────────────────────

-- name: RecentPushPairings :one
-- How many pairing codes the user was issued in the last hour, and when the
-- oldest of them was (now when there are none).
SELECT count(*)::int AS issued, COALESCE(min(created_at), NOW())::timestamptz AS oldest FROM auth.mfa_push_pairings
WHERE user_id = @user_id AND created_at > NOW() - INTERVAL '1 hour';

-- name: ExpireLivePushPairings :exec
-- Ends the user's unused pairing codes, so only the newest works.
UPDATE auth.mfa_push_pairings SET expires_at = NOW()
WHERE user_id = @user_id AND used_at IS NULL AND expires_at > NOW();

-- name: InsertPushPairing :one
INSERT INTO auth.mfa_push_pairings (user_id, organization_id, code_hash, expires_at)
VALUES (@user_id, sqlc.narg('organization_id'), @code_hash, NOW() + make_interval(secs => @ttl_seconds::float8))
RETURNING id, expires_at;

-- name: GetPushPairing :one
SELECT expires_at, used_at, device_id FROM auth.mfa_push_pairings WHERE id = @id AND user_id = @user_id;

-- name: WithdrawPushPairing :one
-- Ends the user's pairing code unless it already linked a phone, and says
-- whether the code is the user's at all.
WITH withdrawn AS (
    UPDATE auth.mfa_push_pairings SET expires_at = LEAST(expires_at, NOW())
    WHERE id = @id AND user_id = @user_id AND used_at IS NULL
    RETURNING id
)
SELECT EXISTS (SELECT 1 FROM auth.mfa_push_pairings p WHERE p.id = @id AND p.user_id = @user_id)::bool AS found;

-- name: ClaimablePushPairing :one
-- The live pairing code with this hash of an active account, locked for the
-- claim that uses it up.
SELECT p.id, p.user_id, p.organization_id, u.email
FROM auth.mfa_push_pairings p
JOIN account.users u ON u.id = p.user_id
WHERE p.code_hash = @code_hash AND p.used_at IS NULL AND p.expires_at > NOW()
  AND u.status = 'active' AND u.deleted_at IS NULL
FOR UPDATE OF p;

-- name: UsePushPairing :exec
UPDATE auth.mfa_push_pairings SET used_at = NOW(), device_id = @device_id WHERE id = @id;

-- name: PurgeExpiredPushPairings :execrows
DELETE FROM auth.mfa_push_pairings WHERE ctid = ANY(ARRAY(
    SELECT p.ctid FROM auth.mfa_push_pairings p WHERE p.expires_at < @cutoff LIMIT @max_rows));
