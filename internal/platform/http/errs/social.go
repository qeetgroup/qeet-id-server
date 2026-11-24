package errs

// Social login errors; ceremony and upstream failures are retryable.
// ErrSocialProviderDisabled is no longer returned; its code stays reserved.
var (
	ErrSocialProviderDisabled = New("social.provider_disabled", KindInvalid, "That sign-in provider is currently disabled.")
)
