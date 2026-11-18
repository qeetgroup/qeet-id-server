package errs

// MFA error codes.
const (
	CodeMFACodeInvalid        = "mfa.code_invalid"
	CodeMFAAttemptsExceeded   = "mfa.attempts_exceeded"
	CodeMFAEnrollmentRequired = "mfa.enrollment_required"
)

// MFA errors. ErrMFACodeSendLimited carries retry_after (seconds) in its
// metadata, and ErrMFAPushPending doesn't count as a failed attempt.
var (
	ErrMFACodeInvalid        = New(CodeMFACodeInvalid, KindUnauthenticated, "That verification code is incorrect or expired.")
	ErrMFAEnrollNotStarted   = New("mfa.enroll_not_started", KindInvalid, "Start MFA setup before confirming.")
	ErrMFAAttemptsExceeded   = New(CodeMFAAttemptsExceeded, KindTooManyRequests, "Too many verification attempts. Start again or wait before retrying.").AsRetryable()
	ErrMFALocked             = New("mfa.locked", KindForbidden, "Too many wrong codes were entered for this account, so signing in with a second factor is locked. Reset your password to unlock it.")
	ErrMFAEnrollmentRequired = New(CodeMFAEnrollmentRequired, KindForbidden, "Your organization requires two-step verification. Set up an authenticator app to continue.")
	ErrMFACodeSendLimited    = New("mfa.code_send_limited", KindTooManyRequests, "A code was sent recently. Wait a moment before asking for another.").AsRetryable()
	ErrMFADeliveryFailed     = New("mfa.delivery_failed", KindBadGateway, "We couldn't send your code. Try again in a moment, or use another way to verify.").AsRetryable()

	ErrMFAPushChallengeExpired = New("mfa.push_challenge_expired", KindGone, "This push challenge has expired. Try signing in again.")
	ErrMFAPushPending          = New("mfa.push_pending", KindConflict, "Approve the sign-in on your phone to continue.").AsRetryable()
)
