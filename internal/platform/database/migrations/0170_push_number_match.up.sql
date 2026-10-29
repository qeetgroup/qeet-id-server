-- 0170_push_number_match — a push approval names the screen that asked.
--
-- A phone could approve a sign-in or step-up it was merely sent, so whoever
-- held the password could send requests until a tired person tapped approve.
-- Each request now carries a two-digit number shown where it was asked for,
-- which the phone must send back to approve it.
ALTER TABLE auth.mfa_push_challenges ADD COLUMN match_number SMALLINT
    CHECK (match_number BETWEEN 10 AND 99);
