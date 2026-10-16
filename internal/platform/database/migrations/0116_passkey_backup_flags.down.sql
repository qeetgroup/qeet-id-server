ALTER TABLE auth.passkey_credentials
    DROP COLUMN IF EXISTS backup_state,
    DROP COLUMN IF EXISTS backup_eligible;
