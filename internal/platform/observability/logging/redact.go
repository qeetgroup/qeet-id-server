package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"unicode"
)

// RedactedValue replaces the value of a sensitive log attribute.
const RedactedValue = "[REDACTED]"

// sensitiveKeys are attribute keys whose values are fully replaced with
// RedactedValue. Keys are compared after normalizeKey.
var sensitiveKeys = normalizeKeys(map[string]struct{}{
	"password":       {},
	"passwd":         {},
	"new_password":   {},
	"old_password":   {},
	"secret":         {},
	"client_secret":  {},
	"signing_secret": {},
	"webhook_secret": {},
	"token":          {},
	"access_token":   {},
	"refresh_token":  {},
	"id_token":       {},
	"bearer":         {},
	// "code" stays redacted: it is the natural key for an OTP or an OAuth
	// authorization code. The one legitimate non-secret use — the stable
	// machine error identifier — logs under "error_code" instead
	// (httpx.WriteError), so this entry costs no diagnostic value.
	"code":                {},
	"otp":                 {},
	"verification_code":   {},
	"authorization_code":  {},
	"device_code":         {},
	"user_code":           {},
	"code_verifier":       {},
	"body":                {},
	"session_token":       {},
	"password_hash":       {},
	"saml_response":       {},
	"assertion":           {},
	"credential":          {},
	"recovery_code":       {},
	"api_key":             {},
	"authorization":       {},
	"proxy-authorization": {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"jwt":                 {},
	"private_key":         {},
	"secret_key":          {},
	"signing_key":         {},
	"encryption_key":      {},
	"client_assertion":    {},
	"dsn":                 {},
	"connection_string":   {},
	"database_url":        {},
	"db_url":              {},
})

// sensitiveSuffixes also redacts any normalized key ending in one of these,
// such as "reset_token", "totp_secret" or "dbPassword".
var sensitiveSuffixes = []string{"token", "secret", "password", "passphrase"}

// partialKeys are attribute keys whose values are partially masked so the
// admin retains some diagnostic ability (e.g. "is this the right user?")
// without exposing full PII. Keys are compared after normalizeKey.
var partialKeys = normalizeKeys(map[string]func(string) string{
	"email":        maskEmail,
	"email_addr":   maskEmail,
	"to":           maskEmail,
	"phone":        maskPhone,
	"phone_number": maskPhone,
})

// normalizeKey lower-cases key and drops '_' and '-', so "clientSecret",
// "client-secret" and "CLIENT_SECRET" all match "client_secret".
func normalizeKey(key string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' {
			return -1
		}
		return unicode.ToLower(r)
	}, key)
}

func normalizeKeys[V any](m map[string]V) map[string]V {
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[normalizeKey(k)] = v
	}
	return out
}

func isSensitiveKey(key string) bool {
	if _, ok := sensitiveKeys[key]; ok {
		return true
	}
	for _, suffix := range sensitiveSuffixes {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

// RedactingHandler wraps a slog.Handler and masks sensitive attribute values by
// key. In the message, string values and the text of error and fmt.Stringer
// values it also removes URL credentials and secret-named key=value values. It
// doesn't reach into other structs; such types should implement slog.LogValuer.
type RedactingHandler struct {
	next slog.Handler
}

// NewRedactingHandler returns a RedactingHandler that writes to next.
func NewRedactingHandler(next slog.Handler) *RedactingHandler {
	return &RedactingHandler{next: next}
}

// Enabled implements slog.Handler.
func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

// Handle implements slog.Handler.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	clone := slog.NewRecord(r.Time, r.Level, redactString(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(redactAttr(a))
		return true
	})
	return h.next.Handle(ctx, clone)
}

// WithAttrs implements slog.Handler.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(out)}
}

// WithGroup implements slog.Handler.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

func redactAttr(a slog.Attr) slog.Attr {
	key := normalizeKey(a.Key)
	if isSensitiveKey(key) {
		return slog.String(a.Key, RedactedValue)
	}
	a.Value = a.Value.Resolve()
	if mask, ok := partialKeys[key]; ok {
		return slog.String(a.Key, mask(a.Value.String()))
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		sub := a.Value.Group()
		out := make([]any, len(sub))
		for i, s := range sub {
			out[i] = redactAttr(s)
		}
		return slog.Group(a.Key, out...)
	case slog.KindString:
		s := a.Value.String()
		if r := redactString(s); r != s {
			return slog.String(a.Key, r)
		}
	case slog.KindAny:
		if s, ok := anyString(a.Value.Any()); ok {
			if r := redactString(s); r != s {
				return slog.String(a.Key, r)
			}
		}
	}
	return a
}

// anyString returns the text of an error or fmt.Stringer value. ok is false
// for other values, and when formatting panics, as a nil receiver can; the
// wrapped handler then reports the panic itself.
func anyString(v any) (s string, ok bool) {
	defer func() {
		if recover() != nil {
			s, ok = "", false
		}
	}()
	switch v := v.(type) {
	case error:
		return v.Error(), true
	case fmt.Stringer:
		return v.String(), true
	}
	return "", false
}

// redactString returns s without URL credentials or the values of
// secret-named keys. It returns s itself, unallocated, when there is nothing
// to remove.
func redactString(s string) string {
	if strings.Contains(s, "://") && strings.IndexByte(s, '@') >= 0 {
		s = StripURLCredentials(s)
	}
	return scrubKeyValues(s)
}

// StripURLCredentials returns s with the userinfo removed from each URL in it,
// so "nats://user:pass@host:4222" becomes "nats://host:4222". A URL's
// authority ends at '/', '?', '#' or whitespace.
func StripURLCredentials(s string) string {
	var b strings.Builder
	last := 0
	for i := 0; ; {
		n := strings.Index(s[i:], "://")
		if n < 0 {
			break
		}
		i += n + len("://")
		end := strings.IndexAny(s[i:], "/?# \t\r\n")
		if end < 0 {
			end = len(s) - i
		}
		if at := strings.LastIndexByte(s[i:i+end], '@'); at >= 0 {
			b.WriteString(s[last:i])
			last = i + at + 1
			i = last
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// textKeys are the key names, compared after normalizeKey, whose values
// scrubKeyValues replaces; a name ending in one of textSuffixes matches too.
var (
	textKeys     = []string{"code", "pwd"}
	textSuffixes = []string{"password", "passwd", "passphrase", "secret", "token", "apikey"}
)

// scrubKeyValues replaces the value of each secret-named key in s and keeps
// the key, in the forms key=value, key: value, "key":"value" and query
// strings, so "?code=abc&state=x" becomes "?code=[REDACTED]&state=x".
func scrubKeyValues(s string) string {
	if !strings.ContainsAny(s, "=:") {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); {
		if !isKeyByte(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && isKeyByte(s[i]) {
			i++
		}
		if !isTextKey(s[start:i]) {
			continue
		}
		vs, ve, ok := valueAfter(s, i)
		if !ok {
			continue
		}
		if last == 0 {
			b.Grow(len(s))
		}
		b.WriteString(s[last:vs])
		b.WriteString(RedactedValue)
		last, i = ve, ve
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// valueAfter returns the bounds of the value after a key that ends at i: an
// optional closing quote, '=' or ':' with optional spaces around it, then a
// quoted value, or one that runs to a space, '&', ';' or quote.
func valueAfter(s string, i int) (start, end int, ok bool) {
	i = skipBlanks(s, i+len(quoteAt(s, i)))
	if i >= len(s) || (s[i] != '=' && s[i] != ':') {
		return 0, 0, false
	}
	i = skipBlanks(s, i+1)
	if q := quoteAt(s, i); q != "" {
		start = i + len(q)
		n := strings.Index(s[start:], q)
		if n < 0 {
			n = len(s) - start
		}
		return start, start + n, n > 0
	}
	start = i
	for i < len(s) && strings.IndexByte(" \t\r\n&;", s[i]) < 0 && quoteAt(s, i) == "" {
		i++
	}
	return start, i, i > start
}

// quoteAt returns the double or single quote that starts at s[i], possibly
// escaped with a backslash, or "" if there is none.
func quoteAt(s string, i int) string {
	if i < len(s) && (s[i] == '"' || s[i] == '\'') {
		return s[i : i+1]
	}
	if i+1 < len(s) && s[i] == '\\' && (s[i+1] == '"' || s[i+1] == '\'') {
		return s[i : i+2]
	}
	return ""
}

func skipBlanks(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// isKeyByte reports whether c can be part of a key in free text.
func isKeyByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-'
}

// isTextKey reports whether key, after normalizeKey, is one of textKeys or
// ends in one of textSuffixes. key holds only isKeyByte bytes.
func isTextKey(key string) bool {
	for _, k := range textKeys {
		if _, whole := normalizedSuffix(key, k); whole {
			return true
		}
	}
	for _, k := range textSuffixes {
		if match, _ := normalizedSuffix(key, k); match {
			return true
		}
	}
	return false
}

// normalizedSuffix reports whether normalizeKey(key) ends with the lower-case
// word suffix, and whether it is exactly suffix, without allocating.
func normalizedSuffix(key, suffix string) (match, whole bool) {
	i, j := len(key)-1, len(suffix)
	for ; i >= 0 && j > 0; i-- {
		if key[i] == '_' || key[i] == '-' {
			continue
		}
		j--
		if key[i]|0x20 != suffix[j] { // ASCII lower-case
			return false, false
		}
	}
	if j > 0 {
		return false, false
	}
	for ; i >= 0; i-- {
		if key[i] != '_' && key[i] != '-' {
			return true, false
		}
	}
	return true, true
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
