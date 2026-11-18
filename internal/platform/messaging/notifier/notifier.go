// Package notifier sends user-facing email and SMS through SES, SMTP or Twilio.
// A channel with no provider falls back to LogSender, which prints the message
// only in development.
package notifier

import (
	"context"
	"log/slog"
	"strings"
)

// Message is one notification to send.
type Message struct {
	TemplateKey       string            // the template to render
	TemplateVariables map[string]string // values for the template
	OrganizationID    string            // the message's organization ("" for none)
	FromName          string            // the sender's display name
	ReplyTo           string            // the Reply-To address
	To                string            // the recipient's address or phone number
	Channel           string            // "email" or "sms"
	Subject           string            // the email subject
	Body              string            // plain-text body (always set; the fallback for HTML mail)
	HTML              string            // optional HTML alternative for email; ignored for SMS
	Tags              map[string]string // free-form labels; the built-in senders ignore them
}

// Sender sends a Message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// LogSender logs messages for channels with no provider. They carry OTPs and
// reset or magic links, so the body is logged only when Reveal is set, which
// must be development only. Without Reveal the message reaches nobody and Send
// returns ErrEmailProviderUnavailable. The zero value reveals nothing.
type LogSender struct {
	Reveal bool // log the message body; development only
}

// Send implements notifier.Sender.
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
	if !l.Reveal {
		return ErrEmailProviderUnavailable
	}
	return nil
}

// MaskDestination is an email address or phone number a code goes to, as
// people see it and the audit log records it: an address keeps the first
// character of its local part and its domain ("a****@example.com"), a number
// its last three digits ("*********123"). Shorter values are kept as they are.
func MaskDestination(channel, dest string) string {
	if channel == "email" {
		at := strings.IndexByte(dest, '@')
		if at <= 1 {
			return dest
		}
		return dest[:1] + strings.Repeat("*", at-1) + dest[at:]
	}
	if len(dest) <= 3 {
		return dest
	}
	return strings.Repeat("*", len(dest)-3) + dest[len(dest)-3:]
}
