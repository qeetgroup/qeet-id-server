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

	CodeAuthInvalidCredentials       = "auth.invalid_credentials"
	CodeAuthAccountLocked            = "auth.account_locked"
	CodeAuthNotTenantMember          = "auth.not_tenant_member"
	CodeAuthSelfRegistrationDisabled = "auth.self_registration_disabled"
	CodeAuthPasswordWeak             = "auth.password_weak"
	CodeAuthMFAChallengeExpired      = "auth.mfa_challenge_expired"
	CodeAuthRefreshTokenInvalid      = "auth.refresh_token_invalid"
	CodeAuthSessionRevoked           = "auth.session_revoked"
	CodeAuthAccountSuspended         = "auth.account_suspended"
)

var (
	ErrAuthSessionInvalid   = New(CodeAuthSessionInvalid, "Your sign-in session is invalid. Please sign in again.").AsRetryable()
	ErrAuthAccountInactive  = New(CodeAuthAccountInactive, "Your account isn't active. Contact your administrator.")
	ErrAuthEmailExists      = New(CodeAuthEmailExists, "An account with this email already exists.")
	ErrAuthEmailRequired    = New(CodeAuthEmailRequired, "Enter your email address.")
	ErrAuthSessionExpired   = New(CodeAuthSessionExpired, "Your session has expired. Please start again.").AsRetryable()
	ErrAuthPasswordBreached = New(CodeAuthPasswordBreached, "This password has appeared in known data breaches. Please choose a different one.")

	ErrAuthInvalidCredentials       = New(CodeAuthInvalidCredentials, "Invalid email or password.")
	ErrAuthAccountLocked            = New(CodeAuthAccountLocked, "Too many failed attempts. Your account is temporarily locked — please try again later.").AsRetryable()
	ErrAuthNotTenantMember          = New(CodeAuthNotTenantMember, "You're not a member of this organization.")
	ErrAuthSelfRegistrationDisabled = New(CodeAuthSelfRegistrationDisabled, "Self-registration is not enabled for this application.")
	ErrAuthPasswordWeak             = New(CodeAuthPasswordWeak, "Choose a stronger password.")
	ErrAuthMFAChallengeExpired      = New(CodeAuthMFAChallengeExpired, "Your sign-in session expired. Please sign in again.").AsRetryable()
	ErrAuthRefreshTokenInvalid      = New(CodeAuthRefreshTokenInvalid, "Your session is no longer valid. Please sign in again.").AsRetryable()
	ErrAuthSessionRevoked           = New(CodeAuthSessionRevoked, "Your session was revoked. Please sign in again.").AsRetryable()
	ErrAuthAccountSuspended         = New(CodeAuthAccountSuspended, "Your account is no longer active. Please contact your administrator.")
)
