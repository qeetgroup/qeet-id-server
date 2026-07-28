package errs

// Passkey (WebAuthn) error codes. Credential/email errors live in auth.go;
// these are the passkey-specific conditions.
const (
	CodePasskeyExists      = "passkey.already_registered"
	CodePasskeyLoginFailed = "passkey.login_failed"

	CodePasskeyUserNotFound       = "passkey.user_not_found"
	CodePasskeySessionMismatch    = "passkey.session_mismatch"
	CodePasskeySessionInvalid     = "passkey.session_invalid"
	CodePasskeyAttestationInvalid = "passkey.attestation_invalid"
	CodePasskeyAssertionInvalid   = "passkey.assertion_invalid"
	CodePasskeyNoCredentials      = "passkey.no_credentials"
	CodePasskeyMFAFailed          = "passkey.mfa_failed"
	CodePasskeyCeremonyFailed     = "passkey.ceremony_failed"
)

var (
	ErrPasskeyExists      = New(CodePasskeyExists, "This passkey is already registered.")
	ErrPasskeyLoginFailed = New(CodePasskeyLoginFailed, "Passkey sign-in failed. Please try again.")

	ErrPasskeyUserNotFound       = New(CodePasskeyUserNotFound, "We couldn't find an account for that passkey.")
	ErrPasskeySessionMismatch    = New(CodePasskeySessionMismatch, "This passkey session doesn't match your account. Please start again.")
	ErrPasskeySessionInvalid     = New(CodePasskeySessionInvalid, "This passkey session isn't valid for this action. Please start again.")
	ErrPasskeyAttestationInvalid = New(CodePasskeyAttestationInvalid, "We couldn't verify that passkey. Please try registering again.")
	ErrPasskeyAssertionInvalid   = New(CodePasskeyAssertionInvalid, "We couldn't verify that passkey. Please try signing in again.")
	ErrPasskeyNoCredentials      = New(CodePasskeyNoCredentials, "No passkeys are registered for this account.")
	ErrPasskeyMFAFailed          = New(CodePasskeyMFAFailed, "Passkey verification failed. Please try again.")
	ErrPasskeyCeremonyFailed     = New(CodePasskeyCeremonyFailed, "We couldn't start the passkey process. Please try again.")
)
