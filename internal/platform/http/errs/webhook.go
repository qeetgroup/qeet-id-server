package errs

// Webhook errors. The Message is what the end user sees — edit wording here, in
// one place. Handlers just `return errs.ErrWebhookNotFound`, attaching a
// wrapped cause with `.Wrap(err)` when there's an underlying error worth logging.
var (
	ErrWebhookNotFound = New("webhook.not_found", KindNotFound, "That webhook subscription doesn't exist.")
)
