package notifier

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"
)

const (
	smtpDialTimeout = 10 * time.Second
	smtpIOTimeout   = 30 * time.Second
)

// SMTPSender delivers email over SMTP (net/smtp negotiates STARTTLS + auth). It
// is provider-agnostic: point Addr/credentials at Amazon SES, SendGrid,
// Mailgun, Postmark, or any relay. It handles the "email" channel only.
type SMTPSender struct {
	Addr     string // host:port (e.g. "email-smtp.us-east-1.amazonaws.com:587")
	Host     string // host alone, for PLAIN auth's server name
	Username string
	Password string
	From     string // RFC 5322 From, e.g. `Qeet ID <noreply@qeet.in>`
}

func (s SMTPSender) Send(ctx context.Context, m Message) error {
	if m.Channel != "" && m.Channel != "email" {
		return fmt.Errorf("smtp sender: unsupported channel %q", m.Channel)
	}
	if m.To == "" {
		return errors.New("smtp sender: empty recipient")
	}

	// net/smtp.SendMail uses net.Dial with no timeout and ignores ctx, so an
	// unresponsive relay hangs the caller (request handler or worker). Dial with
	// a timeout (honouring ctx) and cap the whole exchange with a deadline.
	dialer := net.Dialer{Timeout: smtpDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", s.Addr, err)
	}
	deadline := time.Now().Add(smtpIOTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(fromAddress(s.From)); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err := c.Rcpt(m.To); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(buildMIME(s.From, m.To, m.Subject, m.Body, m.HTML)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return c.Quit()
}

// buildMIME assembles an RFC 5322 message: a plain-text mail, or — when html is
// non-empty — a multipart/alternative carrying both the text and HTML parts so
// clients render whichever they support.
func buildMIME(from, to, subject, body, html string) []byte {
	// Header values are CR/LF-stripped so untrusted input (a submitted recipient,
	// a user-derived subject) can't smuggle extra headers or a forged body —
	// classic SMTP header injection.
	from = sanitizeHeader(from)
	to = sanitizeHeader(to)
	subject = sanitizeHeader(subject)

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")

	if html == "" {
		b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
		b.WriteString(body)
		return []byte(b.String())
	}

	const boundary = "qeet-alt-boundary-9f2a"
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary)
	// Text part first so clients pick HTML (the last supported part) when able.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n")
	b.WriteString(body)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n")
	b.WriteString(html)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

// sanitizeHeader removes CR/LF from a MIME header value, blocking header
// injection where crafted input (recipient, subject) would otherwise add
// unintended headers such as Bcc.
func sanitizeHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

// fromAddress extracts the bare address (the SMTP envelope sender) from a
// possibly display-name-bearing From header.
func fromAddress(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}
