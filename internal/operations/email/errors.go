package email

import "github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"

// The errors this package returns. A code never changes once shipped: clients
// branch and localize on it, never on the message.
var (
	ErrTemplateNotFound        = errs.New("email.template_not_found", errs.KindNotFound, "That email template doesn't exist.")
	ErrTemplateContentRequired = errs.New("email.template_content_required", errs.KindUnprocessable, "Enter both a subject and a body.")
)
