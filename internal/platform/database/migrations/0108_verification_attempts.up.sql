-- 0108_verification_attempts — cap guesses against a single verification code.
--
-- A verification code is 6 digits: one million combinations, and the confirm
-- routes sit on the generic per-user bucket rather than the tighter "sensitive"
-- one used by the code-sending routes. Nothing bounded how many times a caller
-- could guess a given code before it expired, so an attacker who signed up with
-- an address they do not own could grind the code and end up with a verified
-- email they never controlled — which is then the account of record for
-- billing, recovery and org creation.
--
-- Counting attempts on the code row (rather than per IP or per session) ties
-- the budget to the thing being guessed, so rotating IPs or sessions doesn't
-- reset it. Resends are already throttled, which bounds how fast a fresh budget
-- can be obtained.
--
-- Additive with a default, so older binaries ignore the column.
ALTER TABLE "user".email_verifications
    ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;

ALTER TABLE "user".phone_verifications
    ADD COLUMN IF NOT EXISTS attempts INT NOT NULL DEFAULT 0;
