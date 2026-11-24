package errs

// Sign-in / account / credential error codes (shared by the auth, passkey, and
// invitation flows — anything about the caller's identity or credentials).
const (
	CodeAuthAccountInactive = "auth.account_inactive"
	CodeAuthEmailExists     = "auth.email_exists"

	CodeAuthAccountLocked       = "auth.account_locked"
	CodeAuthPasswordWeak        = "auth.password_weak"
	CodeAuthMFAChallengeExpired = "auth.mfa_challenge_expired"
	CodeAuthSessionRevoked      = "auth.session_revoked"
	CodeAuthLastSignInMethod    = "auth.last_sign_in_method"
	CodeAuthAccountSuspended    = "auth.account_suspended"
	CodeAuthAddressNotAllowed   = "auth.address_not_allowed"
	CodeAuthSSORequired         = "auth.sso_required"
)

// Sign-in errors. ErrAuthMethodDisabled and ErrAuthAddressNotAllowed reveal nothing about the account
// or the rule that matched. ErrAuthSSORequired depends only on the domain
// and names the connections in its metadata. ErrAuthPasswordBreached is no longer returned; its code
// stays reserved.
var (
	ErrAuthAccountInactive  = New(CodeAuthAccountInactive, KindForbidden, "Your account isn't active. Contact your administrator.")
	ErrAuthEmailExists      = New(CodeAuthEmailExists, KindConflict, "An account with this email already exists.")
	ErrAuthEmailRequired    = New("auth.email_required", KindUnprocessable, "Enter your email address.")
	ErrAuthPasswordBreached = New("auth.password_breached", KindUnprocessable, "This password has appeared in known data breaches. Please choose a different one.")

	ErrAuthAccountLocked            = New(CodeAuthAccountLocked, KindTooManyRequests, "Too many failed attempts. Your account is temporarily locked — please try again later.").AsRetryable()
	ErrAuthSelfRegistrationDisabled = New("auth.self_registration_disabled", KindForbidden, "Self-registration is not enabled for this application.")
	ErrAuthMethodDisabled           = New("auth.method_disabled", KindForbidden, "This sign-in method isn't available for this organization. Use another way to sign in.")
	ErrAuthPasswordWeak             = New(CodeAuthPasswordWeak, KindUnprocessable, "Choose a stronger password.")
	ErrAuthMFAChallengeExpired      = New(CodeAuthMFAChallengeExpired, KindUnauthenticated, "Your sign-in session expired. Please sign in again.").AsRetryable()
	ErrAuthSessionRevoked           = New(CodeAuthSessionRevoked, KindUnauthenticated, "Your session was revoked. Please sign in again.").AsRetryable()
	ErrAuthLastSignInMethod         = New(CodeAuthLastSignInMethod, KindConflict, "This is the only way to sign in to this account. Add another — a passkey or a password — before removing it.")
	ErrAuthAccountSuspended         = New(CodeAuthAccountSuspended, KindUnauthenticated, "Your account is no longer active. Please contact your administrator.")
	ErrAuthAddressNotAllowed        = New(CodeAuthAddressNotAllowed, KindForbidden, "Your organization doesn't allow sign-in from this network. Contact your administrator.")
	ErrAuthSSORequired              = New(CodeAuthSSORequired, KindForbidden, "Your organization requires you to sign in with its single sign-on.")
)
