package notifier

import (
	"context"
	"log/slog"
	"net"
)

// Router dispatches a Message to the sender configured for its channel, falling
// back to Default (typically LogSender) for channels with no real provider — so
// dev works with no vendor and a half-configured prod still logs rather than
// dropping silently.
type Router struct {
	Email   Sender
	SMS     Sender
	Default Sender
}

func (r Router) Send(ctx context.Context, m Message) error {
	switch m.Channel {
	case "sms":
		if r.SMS != nil {
			return r.SMS.Send(ctx, m)
		}
	case "email", "":
		if r.Email != nil {
			return r.Email.Send(ctx, m)
		}
	}
	if r.Default != nil {
		return r.Default.Send(ctx, m)
	}
	return LogSender{}.Send(ctx, m)
}

// Config selects the real providers. Empty fields leave a channel on the
// LogSender fallback.
type Config struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFrom       string
}

// New builds a channel-routing Sender from config. Email is wired when an SMTP
// host + From are present; SMS when Twilio credentials are present. Anything
// unconfigured falls back to LogSender. It logs which providers went live so a
// misconfigured deploy is obvious in the boot logs.
func New(c Config) Sender {
	r := Router{Default: LogSender{}}

	if c.SMTPHost != "" && c.SMTPFrom != "" {
		port := c.SMTPPort
		if port == "" {
			port = "587"
		}
		r.Email = SMTPSender{
			Addr:     net.JoinHostPort(c.SMTPHost, port),
			Host:     c.SMTPHost,
			Username: c.SMTPUsername,
			Password: c.SMTPPassword,
			From:     c.SMTPFrom,
		}
		slog.Info("notifier: email via SMTP", "host", c.SMTPHost)
	} else {
		slog.Warn("notifier: no email provider configured — emails will only be logged")
	}

	if c.TwilioAccountSID != "" && c.TwilioAuthToken != "" && c.TwilioFrom != "" {
		r.SMS = TwilioSender{AccountSID: c.TwilioAccountSID, AuthToken: c.TwilioAuthToken, From: c.TwilioFrom}
		slog.Info("notifier: SMS via Twilio")
	}

	return r
}
