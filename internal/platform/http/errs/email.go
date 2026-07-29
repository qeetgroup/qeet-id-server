package errs

// Email-template error codes — stable, namespaced machine identifiers for the
// operations/email context (per-tenant transactional email template overrides).
// Clients branch and localize on these codes, never on the message text.
const (
	CodeEmailTemplateNotFound        = "email.template_not_found"
	CodeEmailTemplateContentRequired = "email.template_content_required"
	CodeEmailTenantInvalid           = "email.tenant_invalid"
	CodeEmailTenantMismatch          = "email.tenant_mismatch"
)

var (
	ErrEmailTemplateNotFound        = New(CodeEmailTemplateNotFound, "That email template doesn't exist.")
	ErrEmailTemplateContentRequired = New(CodeEmailTemplateContentRequired, "Enter both a subject and a body.")
	ErrEmailTenantInvalid           = New(CodeEmailTenantInvalid, "That tenant reference is invalid.")
	ErrEmailTenantMismatch          = New(CodeEmailTenantMismatch, "You can't access another tenant's email templates.")
)
