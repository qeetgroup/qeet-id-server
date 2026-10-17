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
	// Zero-value LogSender: Reveal is false, so no credential is printed.
	return LogSender{}.Send(ctx, m)
}

// Config selects the real providers. Empty fields leave a channel on the
// LogSender fallback.
type Config struct {
	// EmailProvider: "ses-api" routes email through the SES v2 API (for regions
	// with no SMTP endpoint); anything else uses SMTP when SMTPHost is set.
	EmailProvider string
	AWSRegion     string

	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFrom       string

	// Dev enables the LogSender body, so a developer can read an OTP out of the
	// console. It must be false outside development: any channel left without a
	// provider routes live credentials to the log fallback. See LogSender.
	Dev bool
}

// New builds a channel-routing Sender from config. Email is wired when an SMTP
// host + From are present; SMS when Twilio credentials are present. Anything
// unconfigured falls back to LogSender. It logs which providers went live so a
// misconfigured deploy is obvious in the boot logs.
func New(c Config) Sender {
	r := Router{Default: LogSender{Reveal: c.Dev}}

	switch {
	case c.EmailProvider == "ses-api" && c.SMTPFrom != "":
		// SES v2 API — for regions without an SMTP endpoint. Init failure falls
		// back to log-only rather than blocking boot (secure-by-default posture).
		s, err := NewSESv2Sender(context.Background(), c.AWSRegion, c.SMTPFrom)
		if err != nil {
			slog.Error("notifier: SES API sender init failed — emails will only be logged", "err", err)
		} else {
			r.Email = s
			slog.Info("notifier: email via SES API", "region", c.AWSRegion)
		}
	case c.SMTPHost != "" && c.SMTPFrom != "":
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
	default:
		slog.Warn("notifier: no email provider configured — emails will only be logged")
	}

	if c.TwilioAccountSID != "" && c.TwilioAuthToken != "" && c.TwilioFrom != "" {
		r.SMS = TwilioSender{AccountSID: c.TwilioAccountSID, AuthToken: c.TwilioAuthToken, From: c.TwilioFrom}
		slog.Info("notifier: SMS via Twilio")
	} else if !c.Dev {
		slog.Warn("notifier: no SMS provider configured — SMS one-time codes are refused")
	}

	return r
}

// Configured reports whether channel ("email" or "sms") has a way to reach the
// person: a real provider, or, in development, the log that prints the
// message. Outside development the log fallback reaches nobody, so a one-time
// code is refused rather than silently dropped.
func (r Router) Configured(channel string) bool {
	switch channel {
	case "sms":
		if r.SMS != nil {
			return true
		}
	case "email", "":
		if r.Email != nil {
			return true
		}
	}
	switch d := r.Default.(type) {
	case nil:
		return false
	case LogSender:
		return d.Reveal
	default:
		return true
	}
}
