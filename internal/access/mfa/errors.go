package mfa

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeRecentSignIn = "recent_sign_in_required"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrTOTPCodeInvalid     = errs.New("mfa.totp_code_invalid", errs.KindInvalid, "That code is incorrect or has expired. Check your authenticator app and try again.")
	ErrOTPCodeInvalid      = errs.New("mfa.otp_code_invalid", errs.KindInvalid, "That code is invalid or has expired. Request a new code and try again.")
	ErrNotConfirmed        = errs.New("mfa.not_confirmed", errs.KindInvalid, "Confirm your MFA setup first.")
	ErrChannelInvalid      = errs.New("mfa.channel_invalid", errs.KindUnprocessable, "Choose email or SMS.")
	ErrDestinationRequired = errs.New("mfa.destination_required", errs.KindUnprocessable, "Enter where the code should be sent.")
	ErrWebAuthnUnavailable = errs.New("mfa.webauthn_unavailable", errs.KindNotImplemented, "Security-key MFA isn't available yet.")
	ErrNotEnrolled         = errs.New("mfa.not_enrolled", errs.KindInvalid, "Set up multi-factor authentication first.")
	ErrFactorNotConfirmed  = errs.New("mfa.factor_not_confirmed", errs.KindInvalid, "Confirm this factor before requesting a code.")
	ErrDeliveryUnavailable = errs.New("mfa.delivery_unavailable", errs.KindUnavailable, "Codes can't be sent this way right now. Use another way to verify, or ask your administrator.")
	ErrFactorLimit         = errs.New("mfa.factor_limit", errs.KindConflict, "You have set up as many email and SMS codes as an account can have. Remove one to add another.")
	// Push MFA
	ErrPushDeviceNotFound   = errs.New("mfa.push_device_not_found", errs.KindNotFound, "Push device not found.")
	ErrPushChallengeInvalid = errs.New("mfa.push_challenge_invalid", errs.KindConflict, "This push challenge is no longer pending.")
	ErrPushUnauthorized     = errs.New("mfa.push_unauthorized", errs.KindUnauthenticated, "Invalid device token.")
	ErrPairingCodeInvalid   = errs.New("mfa.pairing_code_invalid", errs.KindUnauthenticated, "That pairing code is wrong, already used or expired. Ask for a new one on your account's security page.")
	ErrPushDeliveryFailed   = errs.New("mfa.push_delivery_failed", errs.KindBadGateway, "We couldn't reach your phone. Try again, or use another way to verify.").AsRetryable()
	ErrPushLimited          = errs.New("mfa.push_limited", errs.KindTooManyRequests, "Too many approval requests were sent to your phone. Wait a while, or use another way to verify.")
	ErrPushNumberMismatch   = errs.New("mfa.push_number_mismatch", errs.KindForbidden, "That number doesn't match the one on the sign-in screen, so the request was denied.")
	ErrRecentSignIn         = errs.New(CodeRecentSignIn, errs.KindForbidden, "Sign in again to make this change.")
)
