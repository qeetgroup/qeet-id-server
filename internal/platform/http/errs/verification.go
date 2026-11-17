package errs

// Email / phone verification error codes.
const (
	CodeVerifyCodeInvalid      = "verification.code_invalid"
	CodeVerifyCodeUsed         = "verification.code_used"
	CodeVerifyCodeExpired      = "verification.code_expired"
	CodeVerifyAttemptsExceeded = "verification.attempts_exceeded"
	// Sending: too soon after the last code, or past an hourly limit (retry_after, in seconds).
	CodeVerifyCodeSendLimited = "verification.code_send_limited"
	// Sending: no provider is set up to deliver the channel's codes.
	CodeVerifyDeliveryUnavailable = "verification.delivery_unavailable"

	// Preconditions of the send-a-code flow (start email/phone verification).
	CodeVerifyUserNotFound = "verification.user_not_found"
	CodeVerifyNoEmail      = "verification.no_email"
	CodeVerifyNoPhone      = "verification.no_phone"

	// Gate for actions that require a verified email (e.g. creating an org).
	CodeEmailNotVerified = "verification.email_not_verified"

	// Email-change flow: the requested new address already belongs to an account.
	CodeEmailTaken = "verification.email_taken"
	// Email-change flow: an organization holds the address or its domain.
	CodeVerifyEmailManaged = "verification.email_managed"
)

var (
	ErrVerifyCodeInvalid = New(CodeVerifyCodeInvalid, "That verification code is incorrect.")
	ErrVerifyCodeUsed    = New(CodeVerifyCodeUsed, "This code has already been used.")
	ErrVerifyCodeExpired = New(CodeVerifyCodeExpired, "This code has expired. Request a new one.")

	ErrVerifyAttemptsExceeded = New(CodeVerifyAttemptsExceeded,
		"Too many incorrect attempts. Request a new code.").AsRetryable()
	ErrVerifyCodeSendLimited = New(CodeVerifyCodeSendLimited,
		"A code was sent recently. Wait a moment before asking for another.").AsRetryable()
	ErrVerifyDeliveryUnavailable = New(CodeVerifyDeliveryUnavailable, "Codes can't be sent this way right now.")

	ErrVerifyUserNotFound = New(CodeVerifyUserNotFound, "We couldn't find that user.")
	ErrVerifyNoEmail      = New(CodeVerifyNoEmail, "This account has no email address to verify.")
	ErrVerifyNoPhone      = New(CodeVerifyNoPhone, "This account has no phone number to verify. Add one first.")

	ErrEmailNotVerified = New(CodeEmailNotVerified, "Verify your email address before creating an organization.")
	ErrEmailTaken       = New(CodeEmailTaken, "That email address is already in use by another account.")
	// ErrVerifyEmailManaged refuses an email change an organization decides; each
	// refusal says which (an address its directory or single sign-on provides,
	// one on its domains, or a new one on another organization's domain).
	ErrVerifyEmailManaged = New(CodeVerifyEmailManaged, "Your organization manages this email address, so it can't be changed here.")
)
