package httpx

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// Codes callers compare an error with.
const (
	CodeCSRFFailed = "csrf_failed"
)

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrAuthApplicationToken  = errs.New("auth.application_token", errs.KindForbidden, "This token was issued to an application and can't be used here. Sign in to Qeet ID to manage your account.")
	ErrOrganizationLastOwner = errs.New("organization.last_owner", errs.KindConflict, "This is the organization's last owner. Make someone else an owner first.")
	// ErrCSRFFailed refuses a cookie-authenticated mutation from an origin that is
	// not allowed, or without the CSRF cookie echoed in X-CSRF-Token.
	ErrCSRFFailed = errs.New(CodeCSRFFailed, errs.KindForbidden, "This request could not be verified. Reload the page and try again.")
	// ErrUnsupportedMediaType refuses a body not sent as JSON on a route that
	// accepts only JSON.
	ErrUnsupportedMediaType = errs.New("unsupported_media_type", errs.KindUnsupportedMedia, "Send the request body as JSON.")
)
