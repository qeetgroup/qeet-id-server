-- 0168_session_signed_in_at — when the sign-in behind a session happened.
--
-- A session opened by switching to, joining or creating an organisation
-- continues the sign-in it was opened from, so its creation time isn't when
-- the person last proved who they are. A change that needs a recent sign-in
-- reads this instead.
ALTER TABLE auth.sessions ADD COLUMN signed_in_at TIMESTAMPTZ;
UPDATE auth.sessions SET signed_in_at = created_at;
ALTER TABLE auth.sessions ALTER COLUMN signed_in_at SET DEFAULT NOW(),
                          ALTER COLUMN signed_in_at SET NOT NULL;
