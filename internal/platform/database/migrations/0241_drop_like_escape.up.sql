-- 0252_drop_like_escape — LIKE patterns are escaped once, in Go (postgres.EscapeLike), at every
-- search; the SQL copy the audit and activity searches used is no longer called.
DROP FUNCTION IF EXISTS audit.like_escape(TEXT);
