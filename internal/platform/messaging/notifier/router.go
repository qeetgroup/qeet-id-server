package notifier

import (
	"context"
	"log/slog"
	"net"
)

// Router sends each Message through its channel's sender, or Default when the
// channel has none. EmailProviderName ("ses", "smtp") names the email transport
// in delivery records.
type Router struct {
	Email             Sender
	SMS               Sender
	Default           Sender
	EmailProviderName string
}

// EmailProvider names the email transport, "none" when there is none.
func (r Router) EmailProvider() string {
	if r.Email == nil || r.EmailProviderName == "" {
		return "none"
	}
	return r.EmailProviderName
}

// SendID is Send, also returning the email provider's id for the message when
// it gives one (SES does; SMTP doesn't).
func (r Router) SendID(ctx context.Context, m Message) (string, error) {
	if (m.Channel == "email" || m.Channel == "") && r.Email != nil {
		if s, ok := r.Email.(interface {
			SendID(context.Context, Message) (string, error)
		}); ok {
			return s.SendID(ctx, m)
		}
	}
	return "", r.Send(ctx, m)
}

// Send implements notifier.Sender.
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
	EmailProvider       string // "ses-api" for the SES v2 API; otherwise SMTP when SMTPHost is set
	AWSRegion           string // the SES region; empty uses AWS_REGION
	SESConfigurationSet string // SES configuration set for delivery events (ses-api only)

	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	SMTPFrom     string

	TwilioAccountSID string
	TwilioAuthToken  string
	TwilioFrom       string

	Dev bool // reveal LogSender bodies; must be false outside development
}

// New returns a Router built from c: email through the SES API or SMTP, SMS
// through Twilio, and LogSender for anything unconfigured. It logs which
// providers are live.
func New(c Config) Sender {
	r := Router{Default: LogSender{Reveal: c.Dev}}

	switch {
	case c.EmailProvider == "ses-api" && c.SMTPFrom != "":
		// SES v2 API — for regions without an SMTP endpoint. Init failure falls
		// back to log-only rather than blocking boot (secure-by-default posture).
		s, err := NewSESv2Sender(context.Background(), c.AWSRegion, c.SMTPFrom, c.SESConfigurationSet)
		if err != nil {
			slog.Error("notifier: SES API sender init failed — emails will only be logged", "err", err)
		} else {
			r.Email, r.EmailProviderName = s, "ses"
			slog.Info("notifier: email via SES API", "region", c.AWSRegion, "configuration_set", c.SESConfigurationSet)
		}
	case c.SMTPHost != "" && c.SMTPFrom != "":
		port := c.SMTPPort
		if port == "" {
			port = "587"
		}
		r.Email, r.EmailProviderName = SMTPSender{
			Addr:     net.JoinHostPort(c.SMTPHost, port),
			Host:     c.SMTPHost,
			Username: c.SMTPUsername,
			Password: c.SMTPPassword,
			From:     c.SMTPFrom,
		}, "smtp"
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
