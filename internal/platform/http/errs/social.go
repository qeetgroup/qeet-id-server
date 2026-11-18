package errs

// Social login (external OIDC provider) error codes.
const (
	CodeSocialProviderNotConfigured = "social.provider_not_configured"
)

// Social login errors; ceremony and upstream failures are retryable.
// ErrSocialProviderNotConfigured also covers a switched-off provider, and
// ErrSocialAccountNotInOrganization is vague so it reveals no other organization's address.
// ErrSocialProviderDisabled is no longer returned; its code stays reserved.
var (
	ErrSocialProviderNotConfigured = New(CodeSocialProviderNotConfigured, KindNotFound, "That sign-in option isn't available for this organization.")
	ErrSocialProviderDisabled      = New("social.provider_disabled", KindInvalid, "That sign-in provider is currently disabled.")

	ErrSocialAccountNotInOrganization = New("social.account_not_in_organization", KindForbidden, "That account can't sign in with this provider.")
)
