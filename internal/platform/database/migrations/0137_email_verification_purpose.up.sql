-- 0137_email_verification_purpose — say which flow issued each email code.
--
-- Verify-my-address and change-my-address both wrote to email_verifications
-- with nothing telling the rows apart, so a code sent to a new address for an
-- address change could be submitted to verify the address on file instead.
-- Existing rows are labelled by the address they were sent to: one that is not
-- the account's current address can only be an address-change code.
ALTER TABLE "user".email_verifications ADD COLUMN purpose TEXT NOT NULL DEFAULT 'verify_email';

UPDATE "user".email_verifications ev
SET purpose = 'change_email'
FROM "user".users u
WHERE u.id = ev.user_id AND lower(ev.email) <> lower(u.email);

ALTER TABLE "user".email_verifications ALTER COLUMN purpose DROP DEFAULT;

ALTER TABLE "user".email_verifications
    ADD CONSTRAINT email_verifications_purpose_check CHECK (purpose IN ('verify_email', 'change_email'));
