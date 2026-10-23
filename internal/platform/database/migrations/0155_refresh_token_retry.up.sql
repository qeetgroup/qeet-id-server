-- 0155_refresh_token_retry — a rotated refresh token keeps the pair its
-- rotation issued, sealed, for the reuse grace (REFRESH_TOKEN_REUSE_GRACE).
--
-- A client that sends the token again within the grace, because two of its
-- instances renewed at once or it lost the answer, gets that pair instead of
-- having its session ended as theft. The cleanup clears the sealed pair soon
-- after the grace, so it is kept only for minutes.
ALTER TABLE auth.refresh_tokens
    ADD COLUMN replacement_enc   BYTEA,
    ADD COLUMN replacement_nonce BYTEA;

CREATE INDEX idx_refresh_tokens_replacement ON auth.refresh_tokens (used_at) WHERE replacement_enc IS NOT NULL;
