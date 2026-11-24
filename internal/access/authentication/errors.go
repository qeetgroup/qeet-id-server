package authentication

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeInvalidCredentials  = "auth.invalid_credentials"
	CodeRefreshTokenInvalid = "auth.refresh_token_invalid"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrInvalidCredentials          = errs.New(CodeInvalidCredentials, errs.KindUnauthenticated, "Invalid email or password.")
	ErrNotOrganizationMember       = errs.New("auth.not_organization_member", errs.KindForbidden, "You're not a member of this organization.")
	ErrRiskVerificationUnavailable = errs.New("auth.risk_verification_unavailable", errs.KindForbidden, "We couldn't confirm this sign-in. Ask your administrator for help, or set up two-step verification from a device you usually use.")
	ErrRefreshTokenInvalid         = errs.New(CodeRefreshTokenInvalid, errs.KindUnauthenticated, "Your session is no longer valid. Please sign in again.").AsRetryable()
	ErrSessionTimedOut             = errs.New("auth.session_timed_out", errs.KindUnauthenticated, "Your session has timed out. Please sign in again.").AsRetryable()
	ErrSessionLimit                = errs.New("auth.session_limit", errs.KindForbidden, "You're signed in on too many devices for this organization. Sign out of one of them, then try again.")
	ErrOrganizationInactive        = errs.New("auth.organization_inactive", errs.KindForbidden, "This organization isn't active. Contact its administrator.")
	ErrSessionInvalid              = errs.New("auth.session_invalid", errs.KindInvalid, "Your sign-in session is invalid. Please sign in again.").AsRetryable()
	// ErrSignInUnavailable reveals nothing about the account or the rule that matched.
	ErrSignInUnavailable = errs.New("auth.sign_in_unavailable", errs.KindUnavailable, "Sign-in is temporarily unavailable. Please try again in a moment.").AsRetryable()
)
