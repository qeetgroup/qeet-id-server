DROP INDEX IF EXISTS auth.idx_refresh_tokens_replacement;
ALTER TABLE auth.refresh_tokens
    DROP COLUMN IF EXISTS replacement_nonce,
    DROP COLUMN IF EXISTS replacement_enc;
