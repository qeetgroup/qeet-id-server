-- 0116_passkey_backup_flags — store each passkey's backup flags.
--
-- A WebAuthn credential reports two flags: backup eligible (BE: the passkey
-- can be synced to other devices, like iCloud Keychain and Google Password
-- Manager passkeys) and backup state (BS: it is synced right now). BE never
-- changes for a credential, and go-webauthn rejects a login whose BE differs
-- from the one stored at registration. auth.passkey_credentials (migration
-- 0011) had no columns for them, so every synced passkey failed login and
-- passkey MFA. BS may change over a credential's life; the login updates it.
--
-- Passkeys registered before this migration read as not backup eligible. A
-- synced one among them keeps failing until it is registered again.
ALTER TABLE auth.passkey_credentials
    ADD COLUMN IF NOT EXISTS backup_eligible BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS backup_state    BOOLEAN NOT NULL DEFAULT false;
