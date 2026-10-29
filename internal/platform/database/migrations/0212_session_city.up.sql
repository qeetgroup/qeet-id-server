-- 0212_session_city — the city a session was opened from, approximately, when
-- a trusted upstream proxy names it (GEO_CITY_HEADER), beside its country.
ALTER TABLE auth.sessions
    ADD COLUMN IF NOT EXISTS city TEXT CHECK (char_length(city) BETWEEN 1 AND 100);
