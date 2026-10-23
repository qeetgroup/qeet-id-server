package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/redis/go-redis/v9"
)

func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	base := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(NewRedactingHandler(base)), buf
}

func parseLine(t *testing.T, b *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatalf("parse json: %v: %s", err, b.String())
	}
	return m
}

func TestRedact_FullMaskSensitiveKeys(t *testing.T) {
	cases := []string{
		"password", "secret", "client_secret", "signing_secret",
		"token", "access_token", "refresh_token", "id_token",
		"code", "otp", "recovery_code", "api_key", "authorization",
		"cookie", "private_key", "client_assertion",
	}
	for _, key := range cases {
		t.Run(key, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("login", key, "super-sensitive-value-xxx")
			m := parseLine(t, buf)
			if got := m[key]; got != RedactedValue {
				t.Errorf("%s = %v, want %s", key, got, RedactedValue)
			}
		})
	}
}

func TestRedact_CaseInsensitiveKey(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "PASSWORD", "abc", "AUTHorization", "Bearer abc")
	m := parseLine(t, buf)
	if m["PASSWORD"] != RedactedValue {
		t.Errorf("case-insensitive key not redacted: %v", m)
	}
	if m["AUTHorization"] != RedactedValue {
		t.Errorf("case-insensitive key not redacted: %v", m)
	}
}

func TestRedact_EmailPartialMask(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("signup", "email", "alice@example.com")
	m := parseLine(t, buf)
	if m["email"] != "a***@example.com" {
		t.Errorf("email = %v, want a***@example.com", m["email"])
	}
}

func TestRedact_EmailEdgeCases(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"a@b.com":             "*@b.com",
		"notanemail":          RedactedValue,
		"alice@sub.acme.test": "a***@sub.acme.test",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("x", "email", in)
			m := parseLine(t, buf)
			if got, _ := m["email"].(string); got != want {
				t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestRedact_PhonePartialMask(t *testing.T) {
	cases := map[string]string{
		"+1 415-555-1234": "***1234",
		"4155551234":      "***1234",
		"123":             "***",
		"":                "***",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("x", "phone", in)
			m := parseLine(t, buf)
			if got, _ := m["phone"].(string); got != want {
				t.Errorf("maskPhone(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

func TestRedact_GroupRecursion(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("nested", slog.Group("ctx", "password", "p", "email", "bob@example.com", "user_id", "u_123"))
	m := parseLine(t, buf)
	ctx, ok := m["ctx"].(map[string]any)
	if !ok {
		t.Fatalf("expected group, got %T: %v", m["ctx"], m["ctx"])
	}
	if ctx["password"] != RedactedValue {
		t.Errorf("nested password not redacted: %v", ctx)
	}
	if ctx["email"] != "b***@example.com" {
		t.Errorf("nested email not masked: %v", ctx)
	}
	if ctx["user_id"] != "u_123" {
		t.Errorf("non-sensitive value should pass through: %v", ctx)
	}
}

func TestRedact_NonSensitivePassesThrough(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "user_id", "u_1", "tenant_id", "t_1", "duration_ms", 42, "status", 200)
	m := parseLine(t, buf)
	if m["user_id"] != "u_1" || m["tenant_id"] != "t_1" {
		t.Errorf("non-sensitive values should not be touched: %v", m)
	}
	if m["status"] != float64(200) {
		t.Errorf("numeric values should pass through unchanged: %v", m["status"])
	}
}

func TestRedact_WithAttrs(t *testing.T) {
	buf := &bytes.Buffer{}
	base := slog.NewJSONHandler(buf, nil)
	lg := slog.New(NewRedactingHandler(base)).With("password", "p", "user_id", "u_1")
	lg.Info("x")
	m := parseLine(t, buf)
	if m["password"] != RedactedValue {
		t.Errorf("WithAttrs did not redact: %v", m)
	}
	if m["user_id"] != "u_1" {
		t.Errorf("WithAttrs dropped non-sensitive: %v", m)
	}
}

func TestRedact_Enabled(t *testing.T) {
	base := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewRedactingHandler(base)
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Enabled must defer to underlying handler (Info < Warn should be false)")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Enabled must defer to underlying handler (Error > Warn should be true)")
	}
}

func TestRedact_Message(t *testing.T) {
	cases := map[string]string{
		"login failed for password=hunter2":         "login failed for password=[REDACTED]",
		"dial redis://:hunter2@cache:6379/0 failed": "dial redis://cache:6379/0 failed",
		"callback https://app.example/cb?code=abc":  "callback https://app.example/cb?code=[REDACTED]",
		"user signed in": "user signed in",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info(in, "user_id", "u")
			m := parseLine(t, buf)
			if m["msg"] != want {
				t.Errorf("msg = %v, want %s", m["msg"], want)
			}
			if m["user_id"] != "u" {
				t.Errorf("user_id = %v, want u", m["user_id"])
			}
		})
	}
}

func TestRedact_KeySpellingVariants(t *testing.T) {
	keys := []string{
		"clientSecret", "client-secret", "accessToken", "Refresh-Token",
		"apiKey", "API-Key", "X-Api-Key", "Set-Cookie", "newPassword",
		"privateKey", "codeVerifier", "Proxy-Authorization",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("x", key, "super-sensitive-value-xxx")
			if got := parseLine(t, buf)[key]; got != RedactedValue {
				t.Errorf("%s = %v, want %s", key, got, RedactedValue)
			}
		})
	}
}

func TestRedact_SecretNamesAndSuffixes(t *testing.T) {
	keys := []string{
		"passwd", "passphrase", "dsn", "jwt", "secret_key", "signing_key",
		"encryption_key", "connection_string", "database_url", "db_url",
		"reset_token", "csrf_token", "invite_token", "X-Auth-Token",
		"totp_secret", "db_password", "current_password", "key_passphrase",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("x", key, "super-sensitive-value-xxx")
			if got := parseLine(t, buf)[key]; got != RedactedValue {
				t.Errorf("%s = %v, want %s", key, got, RedactedValue)
			}
		})
	}
}

func TestRedact_OrdinaryKeysPassThrough(t *testing.T) {
	keys := []string{
		"key", "key_id", "api_key_id", "client_id", "session_id", "token_type",
		"tokens", "max_tokens", "error_code", "status_code", "codes", "secret_id",
		"password_set", "url", "endpoint", "host", "route", "event",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("x", key, "ordinary-value")
			if got := parseLine(t, buf)[key]; got != "ordinary-value" {
				t.Errorf("%s = %v, want it unchanged", key, got)
			}
		})
	}
}

type loginAttempt struct{ user, password string }

func (l loginAttempt) LogValue() slog.Value {
	return slog.GroupValue(slog.String("user", l.user), slog.String("password", l.password))
}

func TestRedact_LogValuerGroup(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "attempt", loginAttempt{user: "u_1", password: "hunter2"})
	got, ok := parseLine(t, buf)["attempt"].(map[string]any)
	if !ok {
		t.Fatalf("expected group, got %s", buf.String())
	}
	if got["password"] != RedactedValue || got["user"] != "u_1" {
		t.Errorf("attempt = %v", got)
	}
}

func TestRedact_URLCredentialsRemoved(t *testing.T) {
	cases := map[string]string{
		"nats://user:pa55@nats.internal:4222":                     "nats://nats.internal:4222",
		"nats://s3cr3t-token@nats.internal:4222":                  "nats://nats.internal:4222",
		"nats://a:b@n1:4222,nats://c:d@n2:4222":                   "nats://n1:4222,nats://n2:4222",
		"postgres://app:p%40ss@db:5432/qeet_id?sslmode=require":   "postgres://db:5432/qeet_id?sslmode=require",
		"redis://:pa55@cache:6379/0":                              "redis://cache:6379/0",
		"connect https://u:p@h.example/x failed for bob@acme.com": "connect https://h.example/x failed for bob@acme.com",
		"https://example.com/@team?ref=a@b":                       "https://example.com/@team?ref=a@b",
		"nats://nats.internal:4222":                               "nats://nats.internal:4222",
		"dial nats://u:p@n1:4222 failed for bob@acme.com":         "dial nats://n1:4222 failed for bob@acme.com",
		"bob@acme.com": "bob@acme.com",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Info("x", "url", in)
			if got := parseLine(t, buf)["url"]; got != want {
				t.Errorf("url = %v, want %s", got, want)
			}
		})
	}
}

func TestStripURLCredentials(t *testing.T) {
	cases := map[string]string{
		"nats://user:pa55@nats.internal:4222": "nats://nats.internal:4222",
		"nats://nats.internal:4222":           "nats://nats.internal:4222",
		"":                                    "",
		"not a url":                           "not a url",
	}
	for in, want := range cases {
		if got := StripURLCredentials(in); got != want {
			t.Errorf("StripURLCredentials(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestScrubKeyValues(t *testing.T) {
	cases := map[string]string{
		"https://app.example/cb?code=abc123&state=xyz":           "https://app.example/cb?code=[REDACTED]&state=xyz",
		"/cb#access_token=at-1&token_type=bearer&expires_in=60":  "/cb#access_token=[REDACTED]&token_type=bearer&expires_in=60",
		"?refresh_token=rt-1&client_secret=cs-1&api_key=k-1":     "?refresh_token=[REDACTED]&client_secret=[REDACTED]&api_key=[REDACTED]",
		"host=db port=5432 user=app password=S3cret dbname=qeet": "host=db port=5432 user=app password=[REDACTED] dbname=qeet",
		"host=db password = S3cret sslmode=require":              "host=db password = [REDACTED] sslmode=require",
		"Server=db;Uid=app;Pwd=S3cret;Database=qeet":             "Server=db;Uid=app;Pwd=[REDACTED];Database=qeet",
		"host=db password='two words' dbname=qeet":               "host=db password='[REDACTED]' dbname=qeet",
		"PGPASSWORD=S3cret psql":                                 "PGPASSWORD=[REDACTED] psql",
		"passwd: hunter2":                                        "passwd: [REDACTED]",
		"X-Api-Key: k-1":                                         "X-Api-Key: [REDACTED]",
		"SECRET=abc TOKEN=def":                                   "SECRET=[REDACTED] TOKEN=[REDACTED]",
		"config {Host:db Password:S3cret}":                       "config {Host:db Password:[REDACTED]",
		`body {"refresh_token":"rt-1","expires_in":3600}`:        `body {"refresh_token":"[REDACTED]","expires_in":3600}`,
		`parse "https://idp.example/cb?code=abc": bad`:           `parse "https://idp.example/cb?code=[REDACTED]": bad`,
		`resp "{\"access_token\":\"at-1\"}"`:                     `resp "{\"access_token\":\"[REDACTED]\"}"`,
		"token=":                                                 "token=",
		"password=\"\" host=db":                                  "password=\"\" host=db",
		"status_code=500 error_code=auth.denied max_tokens=10":   "status_code=500 error_code=auth.denied max_tokens=10",
		"token_type=bearer secret_id=s_1 password_set=true":      "token_type=bearer secret_id=s_1 password_set=true",
		"dial tcp 10.0.0.1:5432: connect: connection refused":    "dial tcp 10.0.0.1:5432: connect: connection refused",
		"password reset requested":                               "password reset requested",
	}
	for in, want := range cases {
		if got := scrubKeyValues(in); got != want {
			t.Errorf("scrubKeyValues(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedact_ErrorAndStringerValues(t *testing.T) {
	_, redisErr := redis.ParseURL("redis://:hunter2@cache:6379x/0")
	if redisErr == nil {
		t.Fatal("redis.ParseURL accepted an invalid port")
	}
	credURL, err := url.Parse("https://bob:hunter2@idp.example/token")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"redis.ParseURL error", redisErr, `parse "redis://cache:6379x/0": invalid port ":6379x" after host`},
		{"wrapped error", fmt.Errorf("rate-limit store: %w", redisErr), `rate-limit store: parse "redis://cache:6379x/0": invalid port ":6379x" after host`},
		{"DSN in error", errors.New("open db: host=db password=hunter2 dbname=qeet"), "open db: host=db password=[REDACTED] dbname=qeet"},
		{"query secret in error", errors.New(`GET "https://idp.example/x?access_token=hunter2": timeout`), `GET "https://idp.example/x?access_token=[REDACTED]": timeout`},
		{"URL Stringer", credURL, "https://idp.example/token"},
		{"plain error", errors.New("connection refused"), "connection refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lg, buf := newTestLogger()
			lg.Error("failed", "err", tc.value)
			if strings.Contains(buf.String(), "hunter2") {
				t.Fatalf("secret logged: %s", buf.String())
			}
			if got := parseLine(t, buf)["err"]; got != tc.want {
				t.Errorf("err = %v, want %s", got, tc.want)
			}
		})
	}
}

type nilStringer struct{ s string }

func (n *nilStringer) String() string { return n.s }

func TestRedact_PanickingStringerIsLeftToHandler(t *testing.T) {
	lg, buf := newTestLogger()
	lg.Info("x", "v", (*nilStringer)(nil), "ids", []string{"a=b"})
	m := parseLine(t, buf)
	if _, ok := m["v"]; !ok {
		t.Errorf("v missing: %s", buf.String())
	}
	if ids, _ := m["ids"].([]any); len(ids) != 1 || ids[0] != "a=b" {
		t.Errorf("ids = %v, want [a=b]", m["ids"])
	}
}

func TestRedactString_NoAllocWithoutSecrets(t *testing.T) {
	for _, s := range []string{
		"user signed in",
		"nats://nats.internal:4222",
		"dial tcp 10.0.0.1:5432: connect: connection refused",
		"status_code=500 error_code=auth.denied",
		"https://example.com/@team?ref=a@b",
	} {
		if n := testing.AllocsPerRun(100, func() { _ = redactString(s) }); n != 0 {
			t.Errorf("redactString(%q) allocated %v times", s, n)
		}
	}
}
