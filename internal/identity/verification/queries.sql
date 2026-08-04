-- Queries for the verification domain.
-- All queries are static. Queries that touch "user".users are cross-schema reads
-- that are acceptable here (verification is a "user" subdomain and needs the address
-- on file). audit/outbox are not involved in this domain.

-- GetUserEmail fetches the email address for the given user (used by StartEmail
-- when the caller omits the address so we default to the one on file).
-- name: GetUserEmail :one
SELECT email FROM "user".users WHERE id = $1;

-- GetUserPhone fetches the phone number for the given user (used by StartPhone
-- when the caller omits the number).
-- name: GetUserPhone :one
SELECT phone FROM "user".users WHERE id = $1;

-- name: InsertEmailVerification :exec
INSERT INTO "user".email_verifications (user_id, email, code_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- GetLatestEmailVerification selects the most-recent verification row for the
-- given user + code and locks it for update so concurrent Confirm calls don't race.
-- name: GetLatestEmailVerification :one
SELECT id, expires_at, used_at
FROM "user".email_verifications
WHERE user_id = $1 AND code_hash = $2
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: MarkEmailVerificationUsed :exec
UPDATE "user".email_verifications SET used_at = NOW() WHERE id = $1;

-- EmailTakenByOther reports whether an email already belongs to a *different*
-- account (email is globally unique) — the pre-check for an email change.
-- name: EmailTakenByOther :one
SELECT EXISTS(
    SELECT 1 FROM "user".users WHERE email = @email AND id <> @user_id
)::boolean;

-- GetLatestEmailChange is like GetLatestEmailVerification but also returns the
-- pending new email so confirm can swap it onto the user.
-- name: GetLatestEmailChange :one
SELECT id, email, expires_at, used_at
FROM "user".email_verifications
WHERE user_id = @user_id AND code_hash = @code_hash
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- UpdateUserEmail swaps the user's login email and marks it verified (they just
-- proved control of the new address). May hit the global-unique index if the
-- address was taken between start and confirm — caller maps that to email_taken.
-- name: UpdateUserEmail :execrows
UPDATE "user".users
SET email = @email, email_verified_at = NOW(), updated_at = NOW()
WHERE id = @user_id;

-- name: MarkUserEmailVerified :exec
UPDATE "user".users
SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW()
WHERE id = $1;

-- name: InsertPhoneVerification :exec
INSERT INTO "user".phone_verifications (user_id, phone, code_hash, expires_at)
VALUES ($1, $2, $3, $4);

-- name: GetLatestPhoneVerification :one
SELECT id, expires_at, used_at
FROM "user".phone_verifications
WHERE user_id = $1 AND code_hash = $2
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: MarkPhoneVerificationUsed :exec
UPDATE "user".phone_verifications SET used_at = NOW() WHERE id = $1;

-- name: MarkUserPhoneVerified :exec
UPDATE "user".users
SET phone_verified_at = COALESCE(phone_verified_at, NOW()), updated_at = NOW()
WHERE id = $1;
