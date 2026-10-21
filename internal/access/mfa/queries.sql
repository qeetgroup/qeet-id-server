-- Queries for the access/mfa domain.
-- All static queries are compiled by sqlc into ./dbgen.

-- name: ConfirmMFATOTP :exec
UPDATE auth.mfa_totp SET confirmed_at = NOW() WHERE user_id = $1;

-- name: DeleteMFATOTP :exec
DELETE FROM auth.mfa_totp WHERE user_id = $1;

-- GetMFATOTPConfirmed returns confirmed_at (nullable). Callers check .Valid to test
-- enrollment. Returning the full timestamp avoids sqlc's interface{} inference for
-- IS NOT NULL expressions.

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

-- name: MarkRecoveryCodeUsed :exec
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

-- StepUpState is a session's step-up as its organisation judges it: fresh
-- while inside the organisation's window, and counted only when met by a
-- factor type the organisation accepts (step_up_methods NULL: any). A session
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
LEFT JOIN tenant.security_policies sp ON sp.tenant_id = s.tenant_id;

-- StepUpFactorsHeld says which kinds of factor the user could step up with —
-- a confirmed authenticator app (or its recovery codes), a confirmed email or
-- SMS factor, a passkey while the organisation allows passkeys — and which
-- factor types the organisation counts (NULL: every one).
-- name: StepUpFactorsHeld :one
SELECT
    EXISTS (SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = @user_id AND t.confirmed_at IS NOT NULL)::bool AS totp,
    EXISTS (SELECT 1 FROM auth.mfa_otp_factors f WHERE f.user_id = @user_id AND f.verified_at IS NOT NULL)::bool AS otp,
    (EXISTS (SELECT 1 FROM auth.passkey_credentials c WHERE c.user_id = @user_id)
     AND COALESCE((SELECT ap.passkey_enabled FROM tenant.auth_policy ap WHERE ap.tenant_id = @tenant_id::uuid), TRUE))::bool AS passkeys,
    EXISTS (SELECT 1 FROM auth.mfa_push_devices d WHERE d.user_id = @user_id)::bool AS push,
    (SELECT sp.step_up_methods FROM tenant.security_policies sp WHERE sp.tenant_id = @tenant_id::uuid)::text[] AS step_up_methods;

-- OrgStepUpPolicy is how long a step-up lasts in an organisation and whether
-- it counts every factor type (no organisation, or none set: 5 minutes, yes).
-- name: OrgStepUpPolicy :one
SELECT EXTRACT(EPOCH FROM COALESCE(sp.step_up_window, INTERVAL '5 minutes'))::bigint AS window_seconds,
       (sp.step_up_methods IS NULL)::bool AS every_factor
FROM (SELECT @tenant_id::uuid AS id) q
LEFT JOIN tenant.security_policies sp ON sp.tenant_id = q.id;


-- name: DeleteMFAOTPFactors :exec
DELETE FROM auth.mfa_otp_factors WHERE user_id = $1;

-- name: InsertMFAOTPCode :exec
INSERT INTO auth.mfa_otp_codes (factor_id, code_hash, expires_at)
VALUES ($1, $2, $3);

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
WHERE f.id = $1 AND f.user_id = $2 AND c.code_hash = $3
  AND c.used_at IS NULL AND c.expires_at > NOW()
ORDER BY c.created_at DESC LIMIT 1
FOR UPDATE;

-- name: MarkOTPCodeUsed :exec
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

-- IsTenantMember says whether the user belongs to the organisation: holds a
-- role in it, or has it as their home organisation.
-- name: IsTenantMember :one
SELECT (EXISTS (SELECT 1 FROM rbac.user_roles ur WHERE ur.user_id = @user_id AND ur.tenant_id = @tenant_id)
     OR EXISTS (SELECT 1 FROM "user".users u WHERE u.id = @user_id AND u.tenant_id = @tenant_id AND u.deleted_at IS NULL))::bool;

-- name: DeletePushDevice :execrows
DELETE FROM auth.mfa_push_devices WHERE id = $1 AND user_id = $2;

-- name: InsertPushChallenge :one
INSERT INTO auth.mfa_push_challenges (user_id, action, context)
VALUES ($1, $2, $3)
RETURNING id, user_id, action, context, status, expires_at, created_at;

-- name: GetPushChallenge :one
SELECT id, user_id, action, context, status, expires_at, created_at
FROM auth.mfa_push_challenges WHERE id = $1;

-- name: GetPushChallengeForUpdate :one
SELECT id, user_id, status, expires_at
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

-- name: GetOTPCodeForVerify :one
SELECT c.id
FROM auth.mfa_otp_codes c
JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
WHERE f.user_id = $1 AND f.verified_at IS NOT NULL AND c.code_hash = $2
  AND c.used_at IS NULL AND c.expires_at > NOW()
ORDER BY c.created_at DESC LIMIT 1
FOR UPDATE;

-- LoginFactorCounts says which second factors the user can meet a sign-in
-- challenge with: a confirmed authenticator app, unused recovery codes,
-- passkeys (while the user's organisation allows passkeys) and push devices.
-- name: LoginFactorCounts :one
SELECT
    EXISTS (SELECT 1 FROM auth.mfa_totp t WHERE t.user_id = @user_id AND t.confirmed_at IS NOT NULL) AS totp,
    (SELECT count(*) FROM auth.mfa_recovery_codes r WHERE r.user_id = @user_id AND r.used_at IS NULL)::int AS recovery_codes,
    CASE WHEN COALESCE((SELECT ap.passkey_enabled FROM "user".users u
                        JOIN tenant.auth_policy ap ON ap.tenant_id = u.tenant_id
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
