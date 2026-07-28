package errs

// Email / phone verification error codes.
const (
	CodeVerifyCodeInvalid = "verification.code_invalid"
	CodeVerifyCodeUsed    = "verification.code_used"
	CodeVerifyCodeExpired = "verification.code_expired"

	// Preconditions of the send-a-code flow (start email/phone verification).
	CodeVerifyUserNotFound = "verification.user_not_found"
	CodeVerifyNoEmail      = "verification.no_email"
	CodeVerifyNoPhone      = "verification.no_phone"
)

var (
	ErrVerifyCodeInvalid = New(CodeVerifyCodeInvalid, "That verification code is incorrect.")
	ErrVerifyCodeUsed    = New(CodeVerifyCodeUsed, "This code has already been used.")
	ErrVerifyCodeExpired = New(CodeVerifyCodeExpired, "This code has expired. Request a new one.")

	ErrVerifyUserNotFound = New(CodeVerifyUserNotFound, "We couldn't find that user.")
	ErrVerifyNoEmail      = New(CodeVerifyNoEmail, "This account has no email address to verify.")
	ErrVerifyNoPhone      = New(CodeVerifyNoPhone, "This account has no phone number to verify. Add one first.")
)
