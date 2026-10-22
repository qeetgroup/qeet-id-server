package errs

// Invitation (accept-invite) error codes.
const (
	CodeInviteLinkInvalid      = "invite.link_invalid"
	CodeInviteInvalid          = "invite.invalid"
	CodeInviteExpired          = "invite.expired"
	CodeInviteAccountExists    = "invite.account_exists"
	CodeInviteEmailMismatch    = "invite.email_mismatch"
	CodeInviteEmailNotVerified = "invite.email_not_verified"
)

var (
	ErrInviteLinkInvalid      = New(CodeInviteLinkInvalid, "This invitation link is invalid.")
	ErrInviteInvalid          = New(CodeInviteInvalid, "This invitation is no longer valid.")
	ErrInviteExpired          = New(CodeInviteExpired, "This invitation has expired. Ask for a new one.")
	ErrInviteAccountExists    = New(CodeInviteAccountExists, "You already have an account. Sign in, then accept the invitation.")
	ErrInviteEmailMismatch    = New(CodeInviteEmailMismatch, "This invitation was sent to a different email address.")
	ErrInviteEmailNotVerified = New(CodeInviteEmailNotVerified, "Verify your email address to see and accept your invitations.")
)
