ALTER TABLE auth.sessions DROP COLUMN IF EXISTS hook_claims;
ALTER TABLE auth.sessions DROP COLUMN IF EXISTS superseded_by;
