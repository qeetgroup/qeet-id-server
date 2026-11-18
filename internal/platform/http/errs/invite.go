package errs

var (
	ErrInviteLinkInvalid      = New("invite.link_invalid", KindInvalid, "This invitation link is invalid.")
	ErrInviteAccountExists    = New("invite.account_exists", KindConflict, "You already have an account. Sign in, then accept the invitation.")
	ErrInviteEmailNotVerified = New("invite.email_not_verified", KindForbidden, "Verify your email address to see and accept your invitations.")
)
