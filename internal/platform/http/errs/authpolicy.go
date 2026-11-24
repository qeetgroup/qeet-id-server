package errs

// Auth policy error codes: an organization's password rules and the breached-password check.
const (
	CodeAuthPolicyPasswordTooShort    = "authpolicy.password_too_short"
	CodeAuthPolicyPasswordNoUppercase = "authpolicy.password_no_uppercase"
	CodeAuthPolicyPasswordNoNumber    = "authpolicy.password_no_number"
	CodeAuthPolicyPasswordNoSymbol    = "authpolicy.password_no_symbol"
	CodeAuthPolicyPasswordBreached    = "authpolicy.password_breached"
)

// Auth-policy errors. The Message is what an end user (or admin setting a
// password) sees when the password fails the organization's policy.
var (
	ErrAuthPolicyPasswordTooShort    = New(CodeAuthPolicyPasswordTooShort, KindUnprocessable, "Your password is too short. Please choose a longer one.")
	ErrAuthPolicyPasswordNoUppercase = New(CodeAuthPolicyPasswordNoUppercase, KindUnprocessable, "Your password must contain an uppercase letter.")
	ErrAuthPolicyPasswordNoNumber    = New(CodeAuthPolicyPasswordNoNumber, KindUnprocessable, "Your password must contain a number.")
	ErrAuthPolicyPasswordNoSymbol    = New(CodeAuthPolicyPasswordNoSymbol, KindUnprocessable, "Your password must contain a symbol.")
	ErrAuthPolicyPasswordBreached    = New(CodeAuthPolicyPasswordBreached, KindUnprocessable, "This password has appeared in known data breaches — choose a different one.")
)
