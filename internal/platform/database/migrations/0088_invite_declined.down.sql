ALTER TABLE tenant.invites DROP CONSTRAINT IF EXISTS invites_status_check;
ALTER TABLE tenant.invites ADD CONSTRAINT invites_status_check
    CHECK (status IN ('pending', 'accepted', 'revoked', 'expired'));
