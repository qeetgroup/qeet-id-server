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
	Body    string
	Tags    map[string]string
}

type Sender interface {
	Send(ctx context.Context, m Message) error
}

type LogSender struct{}

func (LogSender) Send(_ context.Context, m Message) error {
	slog.Info("notify",
		"channel", m.Channel,
		"to", m.To,
		"subject", m.Subject,
		"body", m.Body,
	)
	return nil
}
