-- 0143_oidc_refresh_grant_id — name the grant every refresh token belongs to.
--
-- Rotating a refresh token inserts a new row and links the old one to it
-- (replaced_by), so one sign-in's grant is a chain of rows. Revoking a token
-- ended only the row presented, and earlier links stayed live. grant_id is the
-- first row's id, carried along every rotation, so the whole chain can be
-- found and ended at once. Existing chains are backfilled from replaced_by.
ALTER TABLE auth.oidc_refresh_tokens ADD COLUMN grant_id UUID;

WITH RECURSIVE chain (id, root) AS (
    SELECT t.id, t.id
    FROM auth.oidc_refresh_tokens t
    WHERE NOT EXISTS (SELECT 1 FROM auth.oidc_refresh_tokens p WHERE p.replaced_by = t.id)
    UNION ALL
    SELECT t.replaced_by, c.root
    FROM auth.oidc_refresh_tokens t
    JOIN chain c ON t.id = c.id
    WHERE t.replaced_by IS NOT NULL
)
UPDATE auth.oidc_refresh_tokens t SET grant_id = chain.root
FROM chain WHERE t.id = chain.id;

UPDATE auth.oidc_refresh_tokens SET grant_id = id WHERE grant_id IS NULL;

CREATE INDEX idx_oidc_refresh_tokens_grant ON auth.oidc_refresh_tokens (grant_id);
