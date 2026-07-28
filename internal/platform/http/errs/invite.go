package errs

// Invitation (accept-invite) error codes.
const (
	CodeInviteLinkInvalid = "invite.link_invalid"
	CodeInviteInvalid     = "invite.invalid"
	CodeInviteExpired     = "invite.expired"
)

var (
	ErrInviteLinkInvalid = New(CodeInviteLinkInvalid, "This invitation link is invalid.")
	ErrInviteInvalid     = New(CodeInviteInvalid, "This invitation is no longer valid.")
	ErrInviteExpired     = New(CodeInviteExpired, "This invitation has expired. Ask for a new one.")
)
