package notifier

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/smtp"
	"strings"
)

// SMTPSender delivers email over SMTP (net/smtp negotiates STARTTLS + auth). It
// is provider-agnostic: point Addr/credentials at Amazon SES, SendGrid,
// Mailgun, Postmark, or any relay. It handles the "email" channel only.
type SMTPSender struct {
	Addr     string // host:port (e.g. "email-smtp.us-east-1.amazonaws.com:587")
	Host     string // host alone, for PLAIN auth's server name
	Username string
	Password string
	From     string // RFC 5322 From, e.g. `Qeet ID <noreply@qeetid.com>`
}

func (s SMTPSender) Send(_ context.Context, m Message) error {
	if m.Channel != "" && m.Channel != "email" {
		return fmt.Errorf("smtp sender: unsupported channel %q", m.Channel)
	}
	if m.To == "" {
		return errors.New("smtp sender: empty recipient")
	}
	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	return smtp.SendMail(s.Addr, auth, fromAddress(s.From), []string{m.To}, buildMIME(s.From, m.To, m.Subject, m.Body))
}

// buildMIME assembles a minimal text/plain RFC 5322 message.
func buildMIME(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// fromAddress extracts the bare address (the SMTP envelope sender) from a
// possibly display-name-bearing From header.
func fromAddress(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}
