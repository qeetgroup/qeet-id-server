-- 0122_invite_passkey — accept an invitation with a passkey.
--
-- auth.webauthn_sessions.pending_invite_id: the invitation a passkey sign-up
-- ceremony is accepting. The account's email and organisation in the same row
-- are copied from that invitation when the ceremony begins, never taken from
-- the invitee, and the invitation is re-read under lock when it finishes.
-- NULL for an ordinary passkey sign-up. Deleting the invitation ends the
-- ceremony with it.
ALTER TABLE auth.webauthn_sessions
    ADD COLUMN IF NOT EXISTS pending_invite_id UUID REFERENCES tenant.invites(id) ON DELETE CASCADE;
