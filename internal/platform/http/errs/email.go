package errs

// Email template error codes.
const (
	CodeEmailTemplateNotFound        = "email.template_not_found"
	CodeEmailTemplateContentRequired = "email.template_content_required"
	CodeEmailOrganizationInvalid     = "email.tenant_invalid"
	CodeEmailOrganizationMismatch    = "email.tenant_mismatch"
	CodeEmailSuppressed              = "email.suppressed"
	CodeEmailProviderUnavailable     = "email.provider_unavailable"
	CodeEmailWebhookSignature        = "email.webhook_signature_invalid"
	CodeEmailWebhookDisabled         = "email.webhook_disabled"
)

var (
	ErrEmailTemplateNotFound        = New(CodeEmailTemplateNotFound, "That email template doesn't exist.")
	ErrEmailTemplateContentRequired = New(CodeEmailTemplateContentRequired, "Enter both a subject and a body.")
	ErrEmailOrganizationInvalid     = New(CodeEmailOrganizationInvalid, "That tenant reference is invalid.")
	ErrEmailOrganizationMismatch    = New(CodeEmailOrganizationMismatch, "You can't access another tenant's email templates.")
	ErrEmailSuppressed              = New(CodeEmailSuppressed, "We can't send email to this address: earlier mail to it bounced or was reported as spam. Check the address, or ask an administrator to clear it.")
	ErrEmailProviderUnavailable     = New(CodeEmailProviderUnavailable, "We couldn't send this message: no delivery provider is configured. Contact the administrator.")
	ErrEmailWebhookSignature        = New(CodeEmailWebhookSignature, "The notification's signature could not be verified.")
	ErrEmailWebhookDisabled         = New(CodeEmailWebhookDisabled, "Email notifications are not received here.")
)
