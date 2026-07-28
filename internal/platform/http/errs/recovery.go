package errs

// Password-reset / magic-link (account recovery) error codes.
const (
	CodeResetLinkInvalid    = "recovery.reset_link_invalid"
	CodeMagicLinkInvalid    = "recovery.magic_link_invalid"
	CodeRecoveryLinkUsed    = "recovery.link_used"
	CodeRecoveryLinkExpired = "recovery.link_expired"
)

var (
	ErrResetLinkInvalid    = New(CodeResetLinkInvalid, "This reset link is invalid.")
	ErrMagicLinkInvalid    = New(CodeMagicLinkInvalid, "This sign-in link is invalid.")
	ErrRecoveryLinkUsed    = New(CodeRecoveryLinkUsed, "This link has already been used. Request a new one.")
	ErrRecoveryLinkExpired = New(CodeRecoveryLinkExpired, "This link has expired. Request a new one.")
)
