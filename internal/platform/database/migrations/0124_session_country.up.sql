-- 0124_session_country — where a session was opened, approximately.
--
-- country: the ISO 3166-1 alpha-2 country a trusted upstream proxy reported
-- for the request that opened the session (GEO_COUNTRY_HEADER), shown in the
-- person's session list so an unfamiliar one stands out. NULL when the
-- deployment supplies no such signal; never taken from the client.
ALTER TABLE auth.sessions
    ADD COLUMN IF NOT EXISTS country TEXT CHECK (country ~ '^[A-Z]{2}$');
