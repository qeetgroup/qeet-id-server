-- Queries for the access/mfa domain.
-- All static queries are compiled by sqlc into ./dbgen.

-- name: UpsertMFATOTP :exec
INSERT INTO auth.mfa_totp (user_id, secret) VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, confirmed_at = NULL;

-- name: GetMFATOTPSecret :one
SELECT secret FROM auth.mfa_totp WHERE user_id = $1;

-- name: ConfirmMFATOTP :exec
UPDATE auth.mfa_totp SET confirmed_at = NOW() WHERE user_id = $1;

-- name: DeleteMFATOTP :exec
DELETE FROM auth.mfa_totp WHERE user_id = $1;

-- GetMFATOTPConfirmed returns confirmed_at (nullable). Callers check .Valid to test
-- enrollment. Returning the full timestamp avoids sqlc's interface{} inference for
-- IS NOT NULL expressions.

-- name: GetMFATOTPConfirmed :one
SELECT confirmed_at FROM auth.mfa_totp WHERE user_id = $1;

-- GetMFATOTPFull returns the secret and confirmed_at for the Verify path.

-- name: GetMFATOTPFull :one
SELECT secret, confirmed_at FROM auth.mfa_totp WHERE user_id = $1;

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
WHERE user_id = $1 AND used_at IS NULL;

-- name: MarkRecoveryCodeUsed :exec
UPDATE auth.mfa_recovery_codes SET used_at = NOW() WHERE id = $1;

-- name: UpsertMFAVerification :exec
INSERT INTO auth.mfa_verifications (user_id, method, verified_at)
VALUES ($1, $2, NOW())
ON CONFLICT (user_id) DO UPDATE SET method = EXCLUDED.method, verified_at = NOW();

-- name: GetMFAVerification :one
SELECT verified_at FROM auth.mfa_verifications WHERE user_id = $1;

-- name: DeleteMFAOTPFactors :exec
DELETE FROM auth.mfa_otp_factors WHERE user_id = $1;

-- name: InsertMFAOTPCode :exec
INSERT INTO auth.mfa_otp_codes (factor_id, code_hash, expires_at)
VALUES ($1, $2, $3);

-- name: UpsertMFAOTPFactor :one
INSERT INTO auth.mfa_otp_factors (user_id, channel, destination)
VALUES ($1, $2, $3)
ON CONFLICT (user_id, channel, destination) DO UPDATE SET verified_at = NULL
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
UPDATE auth.mfa_otp_codes SET used_at = NOW() WHERE id = $1;

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

-- name: GetOTPCodeForVerify :one
SELECT c.id
FROM auth.mfa_otp_codes c
JOIN auth.mfa_otp_factors f ON f.id = c.factor_id
WHERE f.user_id = $1 AND f.verified_at IS NOT NULL AND c.code_hash = $2
  AND c.used_at IS NULL AND c.expires_at > NOW()
ORDER BY c.created_at DESC LIMIT 1
FOR UPDATE;
