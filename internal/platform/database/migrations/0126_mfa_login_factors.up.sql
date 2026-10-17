-- 0126_mfa_login_factors — a sign-in's second-factor challenge can be met by
-- any factor the person holds, not only an authenticator app.
--
-- passkey_session_id: the passkey ceremony started for this challenge; only
-- an assertion from that ceremony completes it.
-- push_challenge_id: the push approval request sent for this challenge; only
-- its approval completes it, and only once (the challenge is deleted when it
-- completes, so an approval cannot sign anyone in twice).
-- codes_sent: email or SMS codes sent for this challenge, bounded.
ALTER TABLE auth.mfa_login_challenges
    ADD COLUMN IF NOT EXISTS passkey_session_id UUID,
    ADD COLUMN IF NOT EXISTS push_challenge_id UUID,
    ADD COLUMN IF NOT EXISTS codes_sent INT NOT NULL DEFAULT 0;
