package errs

// Invitation (accept-invite) error codes.
const (
	CodeInviteLinkInvalid   = "invite.link_invalid"
	CodeInviteInvalid       = "invite.invalid"
	CodeInviteExpired       = "invite.expired"
	CodeInviteAccountExists = "invite.account_exists"
	CodeInviteEmailMismatch = "invite.email_mismatch"
)

var (
	ErrInviteLinkInvalid = New(CodeInviteLinkInvalid, "This invitation link is invalid.")
	ErrInviteInvalid     = New(CodeInviteInvalid, "This invitation is no longer valid.")
	ErrInviteExpired     = New(CodeInviteExpired, "This invitation has expired. Ask for a new one.")
	// ErrInviteAccountExists: the invited email already has a Qeet ID account, so
	// the anonymous "set a password" accept path can't create a new user (email
	// is globally unique). The invitee must sign in and accept as themselves.
	ErrInviteAccountExists = New(CodeInviteAccountExists, "You already have an account. Sign in, then accept the invitation.")
	// ErrInviteEmailMismatch: an authenticated accept whose invite was addressed
	// to a different email than the signed-in user's.
	ErrInviteEmailMismatch = New(CodeInviteEmailMismatch, "This invitation was sent to a different email address.")
)
