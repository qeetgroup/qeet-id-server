package verification

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeVerifyCodeInvalid = "verification.code_invalid"
	// Email-change flow: an organization holds the address or its domain.
	CodeVerifyEmailManaged = "verification.email_managed"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrVerifyCodeInvalid         = errs.New(CodeVerifyCodeInvalid, errs.KindInvalid, "That verification code is incorrect.")
	ErrVerifyCodeUsed            = errs.New("verification.code_used", errs.KindInvalid, "This code has already been used.")
	ErrVerifyCodeExpired         = errs.New("verification.code_expired", errs.KindInvalid, "This code has expired. Request a new one.")
	ErrVerifyAttemptsExceeded    = errs.New("verification.attempts_exceeded", errs.KindTooManyRequests, "Too many incorrect attempts. Request a new code.").AsRetryable()
	ErrVerifyCodeSendLimited     = errs.New("verification.code_send_limited", errs.KindTooManyRequests, "A code was sent recently. Wait a moment before asking for another.").AsRetryable()
	ErrVerifyDeliveryUnavailable = errs.New("verification.delivery_unavailable", errs.KindUnavailable, "Codes can't be sent this way right now.")
	ErrVerifyUserNotFound        = errs.New("verification.user_not_found", errs.KindNotFound, "We couldn't find that user.")
	ErrVerifyNoEmail             = errs.New("verification.no_email", errs.KindUnprocessable, "This account has no email address to verify.")
	ErrVerifyNoPhone             = errs.New("verification.no_phone", errs.KindUnprocessable, "This account has no phone number to verify. Add one first.")
	ErrEmailTaken                = errs.New("verification.email_taken", errs.KindConflict, "That email address is already in use by another account.")
	// ErrVerifyEmailManaged refuses an email change an organization decides; each
	// refusal says which (an address its directory or single sign-on provides,
	// one on its domains, or a new one on another organization's domain).
	ErrVerifyEmailManaged = errs.New(CodeVerifyEmailManaged, errs.KindForbidden, "Your organization manages this email address, so it can't be changed here.")
)
