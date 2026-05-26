package logger

import (
	"context"
	"log/slog"
	"strings"
)

const RedactedValue = "[REDACTED]"

// sensitiveKeys are attribute keys whose values are fully replaced with
// RedactedValue. Matched case-insensitively.
var sensitiveKeys = map[string]struct{}{
	"password":         {},
	"new_password":     {},
	"old_password":     {},
	"secret":           {},
	"client_secret":    {},
	"signing_secret":   {},
	"webhook_secret":   {},
	"token":            {},
	"access_token":     {},
	"refresh_token":    {},
	"id_token":         {},
	"bearer":           {},
	"code":             {},
	"otp":              {},
	"recovery_code":    {},
	"api_key":          {},
	"apikey":           {},
	"authorization":    {},
	"cookie":           {},
	"set-cookie":       {},
	"x-api-key":        {},
	"private_key":      {},
	"client_assertion": {},
}

// partialKeys are attribute keys whose values are partially masked so the
// admin retains some diagnostic ability (e.g. "is this the right user?")
// without exposing full PII. Matched case-insensitively.
var partialKeys = map[string]func(string) string{
	"email":        maskEmail,
	"email_addr":   maskEmail,
	"to":           maskEmail,
	"phone":        maskPhone,
	"phone_number": maskPhone,
}

// RedactingHandler wraps another slog.Handler and masks sensitive attribute
// values before they reach the underlying handler. It redacts at the
// attribute-key level — sensitive data nested inside arbitrary structs
// passed via slog.Any is not reached. Callers logging structs should
// implement slog.LogValuer to emit pre-redacted attrs.
type RedactingHandler struct {
	next slog.Handler
}

func NewRedactingHandler(next slog.Handler) *RedactingHandler {
	return &RedactingHandler{next: next}
}

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	clone := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, clone)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(out)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	key := strings.ToLower(a.Key)
	if _, ok := sensitiveKeys[key]; ok {
		return slog.String(a.Key, RedactedValue)
	}
	if mask, ok := partialKeys[key]; ok {
		return slog.String(a.Key, mask(a.Value.String()))
	}
	if a.Value.Kind() == slog.KindGroup {
		sub := a.Value.Group()
		out := make([]any, len(sub))
		for i, s := range sub {
			out[i] = redactAttr(s)
		}
		return slog.Group(a.Key, out...)
	}
	return a
}

func maskEmail(s string) string {
	if s == "" {
		return s
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		return RedactedValue
	}
	local := s[:at]
	if len(local) <= 1 {
		return "*" + s[at:]
	}
	return local[:1] + "***" + s[at:]
}

func maskPhone(s string) string {
	digits := strings.Builder{}
	for _, c := range s {
		if c >= '0' && c <= '9' {
			digits.WriteRune(c)
		}
	}
	d := digits.String()
	if len(d) <= 4 {
		return "***"
	}
	return "***" + d[len(d)-4:]
}
