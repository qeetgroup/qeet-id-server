// Package notifier delivers user-facing notifications (email, SMS).
// Production wires in a real provider (SendGrid, Twilio); the LogSender
// just emits a structured log line so flows are testable without a vendor.
package notifier

import (
	"context"
	"log/slog"
)

type Message struct {
	To      string
	Channel string // "email" or "sms"
	Subject string
	Body    string // plain-text body (always set; the fallback for HTML mail)
	// HTML, when set on an email, is sent as the rich alternative alongside Body.
	// Ignored for SMS.
	HTML string
	Tags map[string]string
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

// LogSender is the fallback used when a channel has no real provider. It is a
// *credential sink*: the bodies routed through it carry sign-in OTPs,
// password-reset tokens, magic links and invitation tokens.
//
// Reveal therefore gates the body. In development it is true, because reading
// the code out of the console is the point of the fallback. Outside
// development it must stay false: a deployment whose SMS provider is
// unconfigured (or whose email provider failed to initialise) silently routes
// live credentials here, and slog's redacting handler does NOT cover the "body"
// key — it matches attribute keys, and a reset link is just a string.
//
// The zero value is safe: Reveal defaults to false, so a LogSender constructed
// without going through notifier.New never prints a credential.
type LogSender struct {
	// Reveal logs the message body. Development only — see the type comment.
	Reveal bool
}

func (l LogSender) Send(_ context.Context, m Message) error {
	attrs := []any{
		"channel", m.Channel,
		"to", m.To,
		"subject", m.Subject,
	}
	if l.Reveal {
		attrs = append(attrs, "body", m.Body)
	} else {
		// Record that a credential was dropped on the floor. This line is the
		// operator's signal that a channel is unconfigured and users are not
		// receiving their codes — without printing the code itself.
		attrs = append(attrs, "body", "[SUPPRESSED: no provider configured for this channel]")
	}
	slog.Info("notify", attrs...)
	return nil
}
