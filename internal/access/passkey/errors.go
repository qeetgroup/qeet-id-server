package passkey

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrAuthSessionExpired = errs.New("auth.session_expired", errs.KindInvalid, "Your session has expired. Please start again.").AsRetryable()
	ErrExists             = errs.New("passkey.already_registered", errs.KindConflict, "This passkey is already registered.")
	ErrLoginFailed        = errs.New("passkey.login_failed", errs.KindUnauthenticated, "Passkey sign-in failed. Please try again.")
	ErrUserNotFound       = errs.New("passkey.user_not_found", errs.KindNotFound, "We couldn't find an account for that passkey.")
	ErrSessionMismatch    = errs.New("passkey.session_mismatch", errs.KindInvalid, "This passkey session doesn't match your account. Please start again.")
	ErrSessionInvalid     = errs.New("passkey.session_invalid", errs.KindInvalid, "This passkey session isn't valid for this action. Please start again.")
	ErrAttestationInvalid = errs.New("passkey.attestation_invalid", errs.KindInvalid, "We couldn't verify that passkey. Please try registering again.")
	ErrAssertionInvalid   = errs.New("passkey.assertion_invalid", errs.KindInvalid, "We couldn't verify that passkey. Please try signing in again.")
	ErrNoCredentials      = errs.New("passkey.no_credentials", errs.KindInvalid, "No passkeys are registered for this account.")
	ErrMFAFailed          = errs.New("passkey.mfa_failed", errs.KindUnauthenticated, "Passkey verification failed. Please try again.")
	ErrCeremonyFailed     = errs.New("passkey.ceremony_failed", errs.KindInvalid, "We couldn't start the passkey process. Please try again.")
	ErrCloneDetected      = errs.New("passkey.clone_detected", errs.KindUnauthenticated, "We couldn't verify that passkey. Please contact your administrator.") // signature counter didn't advance; vague on purpose
	ErrDisabled           = errs.New("passkey.disabled", errs.KindForbidden, "Your organization has turned off passkeys.")
	ErrBrowserMismatch    = errs.New("passkey.browser_mismatch", errs.KindForbidden, "This passkey sign-in was started in a different browser. Please start again here.").AsRetryable()
)
