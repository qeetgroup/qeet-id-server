-- Allow an invitee to decline a pending invitation (distinct from an admin
-- revoke, so reporting can tell them apart).
ALTER TABLE tenant.invites DROP CONSTRAINT IF EXISTS invites_status_check;
ALTER TABLE tenant.invites ADD CONSTRAINT invites_status_check
    CHECK (status IN ('pending', 'accepted', 'revoked', 'expired', 'declined'));
