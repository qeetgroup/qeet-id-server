package errs

// Sign-in / account / credential error codes (shared by the auth, passkey, and
// invitation flows — anything about the caller's identity or credentials).
const (
	CodeAuthSessionInvalid   = "auth.session_invalid"
	CodeAuthAccountInactive  = "auth.account_inactive"
	CodeAuthEmailExists      = "auth.email_exists"
	CodeAuthEmailRequired    = "auth.email_required"
	CodeAuthSessionExpired   = "auth.session_expired"
	CodeAuthPasswordBreached = "auth.password_breached"

	CodeAuthInvalidCredentials          = "auth.invalid_credentials"
	CodeAuthAccountLocked               = "auth.account_locked"
	CodeAuthNotTenantMember             = "auth.not_tenant_member"
	CodeAuthSelfRegistrationDisabled    = "auth.self_registration_disabled"
	CodeAuthMethodDisabled              = "auth.method_disabled"
	CodeAuthApplicationToken            = "auth.application_token"
	CodeAuthInsufficientScope           = "auth.insufficient_scope"
	CodeAuthPasswordWeak                = "auth.password_weak"
	CodeAuthMFAChallengeExpired         = "auth.mfa_challenge_expired"
	CodeAuthRiskVerificationUnavailable = "auth.risk_verification_unavailable"
	CodeAuthRefreshTokenInvalid         = "auth.refresh_token_invalid"
	CodeAuthSessionRevoked              = "auth.session_revoked"
	CodeAuthSessionTimedOut             = "auth.session_timed_out"
	CodeAuthLastSignInMethod            = "auth.last_sign_in_method"
	CodeAuthSessionLimit                = "auth.session_limit"
	CodeAuthAccountSuspended            = "auth.account_suspended"
	CodeAuthTenantInactive              = "auth.tenant_inactive"
	CodeAuthSignInUnavailable           = "auth.sign_in_unavailable"
	CodeAuthAddressNotAllowed           = "auth.address_not_allowed"
)

// Sign-in errors. ErrAuthMethodDisabled, ErrAuthSignInUnavailable and
// ErrAuthAddressNotAllowed reveal nothing about the account or the rule that
// matched. ErrAuthPasswordBreached is no longer returned; its code stays reserved.
var (
	ErrAuthSessionInvalid   = New(CodeAuthSessionInvalid, "Your sign-in session is invalid. Please sign in again.").AsRetryable()
	ErrAuthAccountInactive  = New(CodeAuthAccountInactive, "Your account isn't active. Contact your administrator.")
	ErrAuthEmailExists      = New(CodeAuthEmailExists, "An account with this email already exists.")
	ErrAuthEmailRequired    = New(CodeAuthEmailRequired, "Enter your email address.")
	ErrAuthSessionExpired   = New(CodeAuthSessionExpired, "Your session has expired. Please start again.").AsRetryable()
	ErrAuthPasswordBreached = New(CodeAuthPasswordBreached, "This password has appeared in known data breaches. Please choose a different one.")

	ErrAuthInvalidCredentials          = New(CodeAuthInvalidCredentials, "Invalid email or password.")
	ErrAuthAccountLocked               = New(CodeAuthAccountLocked, "Too many failed attempts. Your account is temporarily locked — please try again later.").AsRetryable()
	ErrAuthNotTenantMember             = New(CodeAuthNotTenantMember, "You're not a member of this organization.")
	ErrAuthSelfRegistrationDisabled    = New(CodeAuthSelfRegistrationDisabled, "Self-registration is not enabled for this application.")
	ErrAuthApplicationToken            = New(CodeAuthApplicationToken, "This token was issued to an application and can't be used here. Sign in to Qeet ID to manage your account.")
	ErrAuthInsufficientScope           = New(CodeAuthInsufficientScope, "This application wasn't given permission for this. Sign in to the application again and approve the access it asks for.")
	ErrAuthMethodDisabled              = New(CodeAuthMethodDisabled, "This sign-in method isn't available for this organisation. Use another way to sign in.")
	ErrAuthPasswordWeak                = New(CodeAuthPasswordWeak, "Choose a stronger password.")
	ErrAuthMFAChallengeExpired         = New(CodeAuthMFAChallengeExpired, "Your sign-in session expired. Please sign in again.").AsRetryable()
	ErrAuthRiskVerificationUnavailable = New(CodeAuthRiskVerificationUnavailable,
		"We couldn't confirm this sign-in. Ask your administrator for help, or set up two-step verification from a device you usually use.")
	ErrAuthRefreshTokenInvalid = New(CodeAuthRefreshTokenInvalid, "Your session is no longer valid. Please sign in again.").AsRetryable()
	ErrAuthSessionRevoked      = New(CodeAuthSessionRevoked, "Your session was revoked. Please sign in again.").AsRetryable()
	ErrAuthSessionTimedOut     = New(CodeAuthSessionTimedOut, "Your session has timed out. Please sign in again.").AsRetryable()
	ErrAuthLastSignInMethod    = New(CodeAuthLastSignInMethod, "This is the only way to sign in to this account. Add another — a passkey or a password — before removing it.")
	ErrAuthSessionLimit        = New(CodeAuthSessionLimit, "You're signed in on too many devices for this organisation. Sign out of one of them, then try again.")
	ErrAuthAccountSuspended    = New(CodeAuthAccountSuspended, "Your account is no longer active. Please contact your administrator.")
	ErrAuthTenantInactive      = New(CodeAuthTenantInactive, "This organization isn't active. Contact its administrator.")
	ErrAuthSignInUnavailable   = New(CodeAuthSignInUnavailable, "Sign-in is temporarily unavailable. Please try again in a moment.").AsRetryable()
	ErrAuthAddressNotAllowed   = New(CodeAuthAddressNotAllowed, "Your organisation doesn't allow sign-in from this network. Contact your administrator.")
)
