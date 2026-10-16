-- 0117_oidc_refresh_tokens_user_index — find a user's live application grants.
--
-- auth.oidc_refresh_tokens (migration 0027) is indexed by (client_id, user_id),
-- which serves "this application's grant for this user". Ending every grant a
-- user holds — signing out everywhere, an administrator's force sign-out —
-- asks by user alone, which that index cannot answer, so it would scan every
-- refresh token on the deployment (a row is written on every renewal).
--
-- Partial on revoked_at IS NULL: those queries only ever look for grants that
-- have not been ended yet, and ended rows never come back.
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_user_unrevoked
    ON auth.oidc_refresh_tokens (user_id)
    WHERE revoked_at IS NULL;
