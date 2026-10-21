package errs

// Email-template error codes — stable, namespaced machine identifiers for the
// operations/email context (per-tenant transactional email template overrides).
// Clients branch and localize on these codes, never on the message text.
const (
	CodeEmailTemplateNotFound        = "email.template_not_found"
	CodeEmailTemplateContentRequired = "email.template_content_required"
	CodeEmailTenantInvalid           = "email.tenant_invalid"
	CodeEmailTenantMismatch          = "email.tenant_mismatch"
	CodeEmailSuppressed              = "email.suppressed"
	CodeEmailProviderUnavailable     = "email.provider_unavailable"
	CodeEmailWebhookSignature        = "email.webhook_signature_invalid"
	CodeEmailWebhookDisabled         = "email.webhook_disabled"
)

var (
	ErrEmailTemplateNotFound        = New(CodeEmailTemplateNotFound, "That email template doesn't exist.")
	ErrEmailTemplateContentRequired = New(CodeEmailTemplateContentRequired, "Enter both a subject and a body.")
	ErrEmailTenantInvalid           = New(CodeEmailTenantInvalid, "That tenant reference is invalid.")
	ErrEmailTenantMismatch          = New(CodeEmailTenantMismatch, "You can't access another tenant's email templates.")
	// ErrEmailSuppressed: the address hard-bounced or its owner reported our
	// mail as spam, so nothing more is sent to it until an administrator of the
	// organisation whose mail caused it clears it.
	ErrEmailSuppressed = New(CodeEmailSuppressed, "We can't send email to this address: earlier mail to it bounced or was reported as spam. Check the address, or ask an administrator to clear it.")
	// ErrEmailProviderUnavailable: no email (or SMS) provider is configured, so
	// the message reached nobody. Never reported as a success.
	ErrEmailProviderUnavailable = New(CodeEmailProviderUnavailable, "We couldn't send this message: no delivery provider is configured. Contact the administrator.")
	ErrEmailWebhookSignature    = New(CodeEmailWebhookSignature, "The notification's signature could not be verified.")
	ErrEmailWebhookDisabled     = New(CodeEmailWebhookDisabled, "Email notifications are not received here.")
)
