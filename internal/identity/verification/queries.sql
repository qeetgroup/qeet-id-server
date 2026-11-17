-- Queries for the verification domain.
-- All queries are static. Queries that touch account.users are cross-schema reads
-- that are acceptable here (verification is a "user" subdomain and needs the address
-- on file). audit/outbox are not involved in this domain.

-- GetUserEmail fetches the email address for the given user (used by StartEmail
-- when the caller omits the address so we default to the one on file).
-- name: GetUserEmail :one
SELECT email FROM account.users WHERE id = $1;

-- GetUserPhone fetches the phone number for the given user (used by StartPhone
-- when the caller omits the number).
-- name: GetUserPhone :one
SELECT phone FROM account.users WHERE id = $1;

-- InsertEmailVerification issues a code for one purpose (verify_email or
-- change_email) and expires the user's open codes, so a resend replaces the
-- code before it even if it is then withdrawn, and the two flows can't both be
-- pending; each confirm reads only codes of its own purpose.
-- name: InsertEmailVerification :one
WITH retired AS (
    UPDATE account.email_verifications
    SET expires_at = LEAST(expires_at, NOW())
    WHERE user_id = @user_id AND used_at IS NULL
)
INSERT INTO account.email_verifications (user_id, email, code_hash, expires_at, purpose)
VALUES (@user_id, @email, @code_hash, @expires_at, @purpose)
RETURNING id;

-- name: DeleteEmailVerification :exec
DELETE FROM account.email_verifications WHERE id = $1;

-- LockAccountForCodeSend holds the account while a code is counted against
-- the sending limits and stored, so two sends can't both pass them.
-- name: LockAccountForCodeSend :exec
SELECT 1 FROM account.users WHERE id = @user_id FOR NO KEY UPDATE;

-- EmailCodeSends counts the email codes of the last hour sent to the user and
-- to the address, by any account and ignoring case, each with when the oldest
-- went (now, when none did).
-- name: EmailCodeSends :one
WITH mine AS (
    SELECT v.created_at FROM account.email_verifications v
    WHERE v.user_id = @user_id AND v.created_at > NOW() - INTERVAL '1 hour'
), theirs AS (
    SELECT v.created_at FROM account.email_verifications v
    WHERE lower(v.email) = lower(@email) AND v.created_at > NOW() - INTERVAL '1 hour'
)
SELECT
    (SELECT count(*) FROM mine)::int AS user_sends,
    (SELECT COALESCE(min(created_at), NOW()) FROM mine)::timestamptz AS user_oldest,
    (SELECT count(*) FROM theirs)::int AS address_sends,
    (SELECT COALESCE(min(created_at), NOW()) FROM theirs)::timestamptz AS address_oldest;

-- EmailCodeFailures sums the wrong guesses at the user's codes for purpose
-- sent in the last hour or still open, with when the oldest such code went.
-- name: EmailCodeFailures :one
SELECT COALESCE(sum(attempts), 0)::int AS failures, COALESCE(min(created_at), NOW())::timestamptz AS oldest
FROM account.email_verifications
WHERE user_id = @user_id AND purpose = @purpose AND attempts > 0
  AND (created_at > NOW() - INTERVAL '1 hour' OR expires_at > NOW());

-- GetLatestEmailVerification selects the most-recent verification row for the
-- given user + code and locks it for update so concurrent Confirm calls don't race.
-- name: GetLatestEmailVerification :one
SELECT id, expires_at, used_at
FROM account.email_verifications
WHERE user_id = $1 AND code_hash = $2
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: MarkEmailVerificationUsed :exec
UPDATE account.email_verifications SET used_at = NOW() WHERE id = $1;

-- EmailTakenByOther reports whether an email already belongs to a *different*
-- account (email is unique platform-wide, ignoring case) — the pre-check for an
-- email change.
-- name: EmailTakenByOther :one
SELECT EXISTS(
    SELECT 1 FROM account.users WHERE lower(email) = lower(@email) AND id <> @user_id
)::boolean;

-- GetLatestEmailChange is like GetLatestEmailVerification but also returns the
-- pending new email so confirm can swap it onto the user.
-- name: GetLatestEmailChange :one
SELECT id, email, expires_at, used_at
FROM account.email_verifications
WHERE user_id = @user_id AND code_hash = @code_hash
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- UpdateUserEmail swaps the user's login email and marks it verified (they just
-- proved control of the new address). May hit the global-unique index if the
-- address was taken between start and confirm — caller maps that to email_taken.
-- name: UpdateUserEmail :execrows
UPDATE account.users
SET email = @email, email_verified_at = NOW(), updated_at = NOW()
WHERE id = @user_id;

-- MarkUserEmailVerified marks the account's address verified only when it is
-- the address the code was sent to; zero rows means it isn't.
-- name: MarkUserEmailVerified :execrows
UPDATE account.users
SET email_verified_at = COALESCE(email_verified_at, NOW()), updated_at = NOW()
WHERE id = @user_id AND lower(email) = lower(@email);

-- InsertPhoneVerification issues a phone code and expires the user's open
-- ones, so a resend replaces the code before it even if it is then withdrawn.
-- name: InsertPhoneVerification :one
WITH retired AS (
    UPDATE account.phone_verifications
    SET expires_at = LEAST(expires_at, NOW())
    WHERE user_id = @user_id AND used_at IS NULL
)
INSERT INTO account.phone_verifications (user_id, phone, code_hash, expires_at)
VALUES (@user_id, @phone, @code_hash, @expires_at)
RETURNING id;

-- name: DeletePhoneVerification :exec
DELETE FROM account.phone_verifications WHERE id = $1;

-- PhoneCodeSends is EmailCodeSends for phone codes, by user and by number,
-- with when the user's last code of the hour went (an hour ago, when none did).
-- name: PhoneCodeSends :one
WITH mine AS (
    SELECT v.created_at FROM account.phone_verifications v
    WHERE v.user_id = @user_id AND v.created_at > NOW() - INTERVAL '1 hour'
), theirs AS (
    SELECT v.created_at FROM account.phone_verifications v
    WHERE v.phone = @phone AND v.created_at > NOW() - INTERVAL '1 hour'
)
SELECT
    (SELECT count(*) FROM mine)::int AS user_sends,
    (SELECT COALESCE(min(created_at), NOW()) FROM mine)::timestamptz AS user_oldest,
    (SELECT COALESCE(max(created_at), NOW() - INTERVAL '1 hour') FROM mine)::timestamptz AS user_last,
    (SELECT count(*) FROM theirs)::int AS number_sends,
    (SELECT COALESCE(min(created_at), NOW()) FROM theirs)::timestamptz AS number_oldest;

-- PhoneCodeFailures is EmailCodeFailures for phone codes.
-- name: PhoneCodeFailures :one
SELECT COALESCE(sum(attempts), 0)::int AS failures, COALESCE(min(created_at), NOW())::timestamptz AS oldest
FROM account.phone_verifications
WHERE user_id = @user_id AND attempts > 0
  AND (created_at > NOW() - INTERVAL '1 hour' OR expires_at > NOW());

-- name: GetLatestPhoneVerification :one
SELECT id, phone, expires_at, used_at
FROM account.phone_verifications
WHERE user_id = $1 AND code_hash = $2
ORDER BY created_at DESC
LIMIT 1
FOR UPDATE;

-- name: MarkPhoneVerificationUsed :exec
UPDATE account.phone_verifications SET used_at = NOW() WHERE id = $1;

-- name: MarkUserPhoneVerified :exec
UPDATE account.users
SET phone_verified_at = COALESCE(phone_verified_at, NOW()), updated_at = NOW()
WHERE id = $1;

-- SetUserVerifiedPhone persists the just-verified number AND stamps the verified
-- time. Unlike MarkUserPhoneVerified it writes users.phone and re-stamps the time
-- (no COALESCE) — the number just changed, so its prior verification is void.
-- name: SetUserVerifiedPhone :exec
UPDATE account.users
SET phone = @phone, phone_verified_at = NOW(), updated_at = NOW()
WHERE id = @user_id;

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

-- AddressHolder returns the account's address and organization, and whether
-- that organization's directory or single sign-on provides the address: SCIM
-- provisioned the account, or it is linked to one of its connections.
-- name: AddressHolder :one
SELECT u.email, u.organization_id,
       ((u.provisioned_via IS NOT DISTINCT FROM 'scim') OR EXISTS (
           SELECT 1 FROM account.external_identities e
           WHERE e.user_id = u.id AND e.organization_id = u.organization_id AND e.connection_id IS NOT NULL
       ))::bool AS provided
FROM account.users u WHERE u.id = @user_id;
