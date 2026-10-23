package errs

// MFA error codes.
const (
	CodeMFATOTPCodeInvalid     = "mfa.totp_code_invalid"
	CodeMFAOTPCodeInvalid      = "mfa.otp_code_invalid"
	CodeMFACodeInvalid         = "mfa.code_invalid"
	CodeMFAEnrollNotStarted    = "mfa.enroll_not_started"
	CodeMFANotConfirmed        = "mfa.not_confirmed"
	CodeMFAChannelInvalid      = "mfa.channel_invalid"
	CodeMFADestinationRequired = "mfa.destination_required"
	CodeMFAWebAuthnUnavailable = "mfa.webauthn_unavailable"
	CodeMFANotEnrolled         = "mfa.not_enrolled"
	CodeMFAFactorNotConfirmed  = "mfa.factor_not_confirmed"
	CodeMFAAttemptsExceeded    = "mfa.attempts_exceeded"
	CodeMFAEnrollmentRequired  = "mfa.enrollment_required"
	CodeMFACodeSendLimited     = "mfa.code_send_limited"
	CodeMFADeliveryUnavailable = "mfa.delivery_unavailable"
	CodeMFADeliveryFailed      = "mfa.delivery_failed"
	CodeMFAFactorLimit         = "mfa.factor_limit"

	// Push MFA
	CodeMFAPushDeviceNotFound   = "mfa.push_device_not_found"
	CodeMFAPushChallengeExpired = "mfa.push_challenge_expired"
	CodeMFAPushChallengeInvalid = "mfa.push_challenge_invalid"
	CodeMFAPushUnauthorized     = "mfa.push_unauthorized"
	CodeMFAPushPending          = "mfa.push_pending"
	CodeMFAPairingCodeInvalid   = "mfa.pairing_code_invalid"
	CodeMFAPushDeliveryFailed   = "mfa.push_delivery_failed"
)

// MFA errors. ErrMFACodeSendLimited carries retry_after (seconds) in its
// metadata, and ErrMFAPushPending doesn't count as a failed attempt.
var (
	ErrMFATOTPCodeInvalid     = New(CodeMFATOTPCodeInvalid, "That code is incorrect or has expired. Check your authenticator app and try again.")
	ErrMFAOTPCodeInvalid      = New(CodeMFAOTPCodeInvalid, "That code is invalid or has expired. Request a new code and try again.")
	ErrMFACodeInvalid         = New(CodeMFACodeInvalid, "That verification code is incorrect or expired.")
	ErrMFAEnrollNotStarted    = New(CodeMFAEnrollNotStarted, "Start MFA setup before confirming.")
	ErrMFANotConfirmed        = New(CodeMFANotConfirmed, "Confirm your MFA setup first.")
	ErrMFAChannelInvalid      = New(CodeMFAChannelInvalid, "Choose email or SMS.")
	ErrMFADestinationRequired = New(CodeMFADestinationRequired, "Enter where the code should be sent.")
	ErrMFAWebAuthnUnavailable = New(CodeMFAWebAuthnUnavailable, "Security-key MFA isn't available yet.")
	ErrMFANotEnrolled         = New(CodeMFANotEnrolled, "Set up multi-factor authentication first.")
	ErrMFAFactorNotConfirmed  = New(CodeMFAFactorNotConfirmed, "Confirm this factor before requesting a code.")
	ErrMFAAttemptsExceeded    = New(CodeMFAAttemptsExceeded, "Too many verification attempts. Start again or wait before retrying.").AsRetryable()
	ErrMFAEnrollmentRequired  = New(CodeMFAEnrollmentRequired, "Your organisation requires two-step verification. Set up an authenticator app to continue.")
	ErrMFACodeSendLimited     = New(CodeMFACodeSendLimited, "A code was sent recently. Wait a moment before asking for another.").AsRetryable()
	ErrMFADeliveryUnavailable = New(CodeMFADeliveryUnavailable, "Codes can't be sent this way right now. Use another way to verify, or ask your administrator.")
	ErrMFADeliveryFailed      = New(CodeMFADeliveryFailed, "We couldn't send your code. Try again in a moment, or use another way to verify.").AsRetryable()
	ErrMFAFactorLimit         = New(CodeMFAFactorLimit, "You have set up as many email and SMS codes as an account can have. Remove one to add another.")

	// Push MFA
	ErrMFAPushDeviceNotFound   = New(CodeMFAPushDeviceNotFound, "Push device not found.")
	ErrMFAPushChallengeExpired = New(CodeMFAPushChallengeExpired, "This push challenge has expired. Try signing in again.")
	ErrMFAPushChallengeInvalid = New(CodeMFAPushChallengeInvalid, "This push challenge is no longer pending.")
	ErrMFAPushUnauthorized     = New(CodeMFAPushUnauthorized, "Invalid device token.")
	ErrMFAPushPending          = New(CodeMFAPushPending, "Approve the sign-in on your phone to continue.").AsRetryable()
	ErrMFAPairingCodeInvalid   = New(CodeMFAPairingCodeInvalid, "That pairing code is wrong, already used or expired. Ask for a new one on your account's security page.")
	ErrMFAPushDeliveryFailed   = New(CodeMFAPushDeliveryFailed, "We couldn't reach your phone. Try again, or use another way to verify.").AsRetryable()
)
