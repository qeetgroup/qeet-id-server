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
	CodeAuthPasswordWeak                = "auth.password_weak"
	CodeAuthMFAChallengeExpired         = "auth.mfa_challenge_expired"
	CodeAuthRiskVerificationUnavailable = "auth.risk_verification_unavailable"
	CodeAuthRefreshTokenInvalid         = "auth.refresh_token_invalid"
	CodeAuthSessionRevoked              = "auth.session_revoked"
	CodeAuthSessionTimedOut             = "auth.session_timed_out"
	CodeAuthLastSignInMethod            = "auth.last_sign_in_method"
	CodeAuthSessionLimit                = "auth.session_limit"
	CodeAuthAccountSuspended            = "auth.account_suspended"
	CodeAuthSignInUnavailable           = "auth.sign_in_unavailable"
	CodeAuthAddressNotAllowed           = "auth.address_not_allowed"
)

var (
	ErrAuthSessionInvalid   = New(CodeAuthSessionInvalid, "Your sign-in session is invalid. Please sign in again.").AsRetryable()
	ErrAuthAccountInactive  = New(CodeAuthAccountInactive, "Your account isn't active. Contact your administrator.")
	ErrAuthEmailExists      = New(CodeAuthEmailExists, "An account with this email already exists.")
	ErrAuthEmailRequired    = New(CodeAuthEmailRequired, "Enter your email address.")
	ErrAuthSessionExpired   = New(CodeAuthSessionExpired, "Your session has expired. Please start again.").AsRetryable()
	ErrAuthPasswordBreached = New(CodeAuthPasswordBreached, "This password has appeared in known data breaches. Please choose a different one.") // no longer returned: every password path reports ErrAuthPolicyPasswordBreached; the code stays reserved so it is never reused

	ErrAuthInvalidCredentials       = New(CodeAuthInvalidCredentials, "Invalid email or password.")
	ErrAuthAccountLocked            = New(CodeAuthAccountLocked, "Too many failed attempts. Your account is temporarily locked — please try again later.").AsRetryable()
	ErrAuthNotTenantMember          = New(CodeAuthNotTenantMember, "You're not a member of this organization.")
	ErrAuthSelfRegistrationDisabled = New(CodeAuthSelfRegistrationDisabled, "Self-registration is not enabled for this application.")
	// ErrAuthApplicationToken: the token was issued to an application, which
	// may read who the user is but not manage their account or organisation.
	ErrAuthApplicationToken = New(CodeAuthApplicationToken, "This token was issued to an application and can't be used here. Sign in to Qeet ID to manage your account.")
	// ErrAuthMethodDisabled: the organisation has switched this sign-in method
	// off. An access decision, not a wrong credential; it says nothing about
	// whether an account exists.
	ErrAuthMethodDisabled      = New(CodeAuthMethodDisabled, "This sign-in method isn't available for this organisation. Use another way to sign in.")
	ErrAuthPasswordWeak        = New(CodeAuthPasswordWeak, "Choose a stronger password.")
	ErrAuthMFAChallengeExpired = New(CodeAuthMFAChallengeExpired, "Your sign-in session expired. Please sign in again.").AsRetryable()
	// ErrAuthRiskVerificationUnavailable: the sign-in looks risky and must be
	// confirmed, but the account has neither a second factor nor a verified
	// email address to confirm it with.
	ErrAuthRiskVerificationUnavailable = New(CodeAuthRiskVerificationUnavailable,
		"We couldn't confirm this sign-in. Ask your administrator for help, or set up two-step verification from a device you usually use.")
	ErrAuthRefreshTokenInvalid = New(CodeAuthRefreshTokenInvalid, "Your session is no longer valid. Please sign in again.").AsRetryable()
	ErrAuthSessionRevoked      = New(CodeAuthSessionRevoked, "Your session was revoked. Please sign in again.").AsRetryable()
	// ErrAuthSessionTimedOut: the session reached its maximum age or went
	// unrenewed for longer than its idle timeout, and has ended.
	ErrAuthSessionTimedOut = New(CodeAuthSessionTimedOut, "Your session has timed out. Please sign in again.").AsRetryable()
	// ErrAuthLastSignInMethod refuses removing an account's only remaining way
	// to sign in (a passkey, a password, a linked identity).
	ErrAuthLastSignInMethod = New(CodeAuthLastSignInMethod, "This is the only way to sign in to this account. Add another — a passkey or a password — before removing it.")
	// ErrAuthSessionLimit refuses a sign-in that would exceed the
	// organisation's limit on one person's simultaneous sessions.
	ErrAuthSessionLimit     = New(CodeAuthSessionLimit, "You're signed in on too many devices for this organisation. Sign out of one of them, then try again.")
	ErrAuthAccountSuspended = New(CodeAuthAccountSuspended, "Your account is no longer active. Please contact your administrator.")
	// ErrAuthSignInUnavailable refuses a password sign-in whose failed-attempt
	// counters could not be read or written: the lockout fails closed. The same
	// answer whatever the password and whether the address has an account.
	ErrAuthSignInUnavailable = New(CodeAuthSignInUnavailable, "Sign-in is temporarily unavailable. Please try again in a moment.").AsRetryable()
	// ErrAuthAddressNotAllowed refuses a sign-in, or a session's renewal, from
	// an address the organisation's address rules don't allow. It never says
	// which rule matched.
	ErrAuthAddressNotAllowed = New(CodeAuthAddressNotAllowed, "Your organisation doesn't allow sign-in from this network. Contact your administrator.")
)
