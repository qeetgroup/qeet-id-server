package errs

// MFA error codes — stable, namespaced machine identifiers. Clients branch and
// localize on these (never on the message text). Once shipped, a code MUST NOT
// change. Using constants gives autocomplete, compile-time safety, and lets
// tests reference the exact code without string literals.
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

	// Push MFA
	CodeMFAPushDeviceNotFound   = "mfa.push_device_not_found"
	CodeMFAPushChallengeExpired = "mfa.push_challenge_expired"
	CodeMFAPushChallengeInvalid = "mfa.push_challenge_invalid"
	CodeMFAPushUnauthorized     = "mfa.push_unauthorized"
)

// MFA errors. The Message is what the end user sees — edit wording here, in one
// place. Handlers just `return errs.ErrMFACodeInvalid`, attaching a wrapped
// cause with `.Wrap(err)` when there's an underlying error worth logging.
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

	// Push MFA
	ErrMFAPushDeviceNotFound   = New(CodeMFAPushDeviceNotFound, "Push device not found.")
	ErrMFAPushChallengeExpired = New(CodeMFAPushChallengeExpired, "This push challenge has expired. Try signing in again.")
	ErrMFAPushChallengeInvalid = New(CodeMFAPushChallengeInvalid, "This push challenge is no longer pending.")
	ErrMFAPushUnauthorized     = New(CodeMFAPushUnauthorized, "Invalid device token.")
)
