package errs

// Auth policy error codes: a tenant's password rules and the breached-password check.
const (
	CodeAuthPolicyPasswordTooShort    = "authpolicy.password_too_short"
	CodeAuthPolicyPasswordNoUppercase = "authpolicy.password_no_uppercase"
	CodeAuthPolicyPasswordNoNumber    = "authpolicy.password_no_number"
	CodeAuthPolicyPasswordNoSymbol    = "authpolicy.password_no_symbol"
	CodeAuthPolicyPasswordBreached    = "authpolicy.password_breached"
)

// Auth-policy errors. The Message is what an end user (or admin setting a
// password) sees when the password fails the tenant's policy.
var (
	ErrAuthPolicyPasswordTooShort    = New(CodeAuthPolicyPasswordTooShort, "Your password is too short. Please choose a longer one.")
	ErrAuthPolicyPasswordNoUppercase = New(CodeAuthPolicyPasswordNoUppercase, "Your password must contain an uppercase letter.")
	ErrAuthPolicyPasswordNoNumber    = New(CodeAuthPolicyPasswordNoNumber, "Your password must contain a number.")
	ErrAuthPolicyPasswordNoSymbol    = New(CodeAuthPolicyPasswordNoSymbol, "Your password must contain a symbol.")
	ErrAuthPolicyPasswordBreached    = New(CodeAuthPolicyPasswordBreached, "This password has appeared in known data breaches — choose a different one.")
)
