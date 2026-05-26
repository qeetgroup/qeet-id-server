package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
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

func TestRedact_NoLeakInMessage(t *testing.T) {
	// Sanity: the redaction operates on attributes only, not the message text.
	// This test documents that limitation so future readers don't assume the
	// handler also scrubs free-form messages.
	lg, buf := newTestLogger()
	lg.Info("login failed for password=hunter2", "user_id", "u")
	if !strings.Contains(buf.String(), "hunter2") {
		t.Skip("if message redaction is later added, update this test")
	}
}
