package tokenvault

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeProviderNotFound         = "tokenvault.provider_not_found"
	CodeProviderAuthorizeInvalid = "tokenvault.provider_authorize_url_invalid"
	CodeProviderInUse            = "tokenvault.provider_in_use"
	CodeProviderTokenURLInvalid  = "tokenvault.provider_token_url_invalid"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrProviderNotFound         = errs.New(CodeProviderNotFound, errs.KindNotFound, "That provider isn't registered for your account.")
	ErrProviderAuthorizeInvalid = errs.New(CodeProviderAuthorizeInvalid, errs.KindUnprocessable, "This provider is misconfigured and can't be used to connect.")
	ErrProviderTokenURLInvalid  = errs.New(CodeProviderTokenURLInvalid, errs.KindUnprocessable, "The provider's token URL must be a public http or https URL.")
	ErrProviderInUse            = errs.New(CodeProviderInUse, errs.KindConflict, "People are connected through this provider, so its endpoints and client can't change. Delete it to disconnect them first.")
	ErrConnectStateInvalid      = errs.New("tokenvault.connect_state_invalid", errs.KindInvalid, "This connection link is invalid or has already been used. Please start again.")
	ErrConnectExpired           = errs.New("tokenvault.connect_expired", errs.KindInvalid, "This connection request has expired. Please start again.")
	ErrConnectOtherBrowser      = errs.New("tokenvault.connect_other_browser", errs.KindInvalid, "This connection was started in another browser. Start it again in the browser you are using.")
	ErrTokenExchangeFailed      = errs.New("tokenvault.token_exchange_failed", errs.KindInternal, "We couldn't complete the connection with the provider. Please try again.").AsRetryable()
	ErrTokenExpired             = errs.New("tokenvault.token_expired", errs.KindUnauthenticated, "Your connection to this provider has expired. Please reconnect your account.")
	ErrScopeRequired            = errs.New("tokenvault.scope_required", errs.KindForbidden, "You don't have permission to access this connected account.")
	ErrPeopleOnly               = errs.New("tokenvault.people_only", errs.KindForbidden, "Only the person who connected this account can read its token, while signed in.")
)
