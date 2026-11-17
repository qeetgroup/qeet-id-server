-- 0237_auth_hook_previous_secret — a hook's replaced signing secret goes on
-- signing its calls beside the new one for a while.
--
-- Auth-hook calls are now signed as webhook deliveries are: over a timestamp
-- and the body, with a signature for each secret while a replaced one
-- overlaps its successor, so the hook's endpoint can move to the new secret
-- without refusing calls meanwhile. The replaced secret is kept encrypted, as
-- the current one is, until previous_secret_expires_at.
ALTER TABLE tenant.auth_hooks
    ADD COLUMN previous_secret_ct BYTEA,
    ADD COLUMN previous_secret_nonce BYTEA,
    ADD COLUMN previous_secret_expires_at TIMESTAMPTZ;
