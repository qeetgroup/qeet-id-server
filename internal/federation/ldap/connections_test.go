package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

func TestDefaulted(t *testing.T) {
	if got := defaulted("", "x"); got != "x" {
		t.Errorf("empty should fall back, got %q", got)
	}
	if got := defaulted("   ", "x"); got != "x" {
		t.Errorf("whitespace should fall back, got %q", got)
	}
	if got := defaulted("y", "x"); got != "y" {
		t.Errorf("present value should win, got %q", got)
	}
}

// TestSkipTLSVerifyRefused checks that a connection which turns certificate
// verification off is refused, when saved and when it binds, unless that is
// allowed.
func TestSkipTLSVerifyRefused(t *testing.T) {
	ctx := context.Background()
	svc := unitService(t, production)
	skip := true
	if _, err := svc.Create(ctx, uuid.New(), CreateInput{ServerURL: "ldaps://ad.example.org:636", SkipTLSVerify: true}, audit.Actor{}); !errors.Is(err, ErrTLSVerifyRequired) {
		t.Errorf("create: %v, want %v", err, ErrTLSVerifyRequired)
	}
	if _, err := svc.Update(ctx, uuid.New(), uuid.New(), UpdateInput{SkipTLSVerify: &skip}, audit.Actor{}); !errors.Is(err, ErrTLSVerifyRequired) {
		t.Errorf("update: %v, want %v", err, ErrTLSVerifyRequired)
	}
	c := &connFull{Connection: Connection{ServerURL: "ldaps://127.0.0.1:1", SkipTLSVerify: true}}
	if err := svc.TestBind(ctx, c); !errors.Is(err, ErrTLSVerifyRequired) {
		t.Errorf("test bind: %v, want %v", err, ErrTLSVerifyRequired)
	}
	if _, err := svc.authenticate(ctx, c, "alice", "secret"); !errors.Is(err, ErrTLSVerifyRequired) {
		t.Errorf("sign-in bind: %v, want %v", err, ErrTLSVerifyRequired)
	}

	allowed := unitService(t)
	if err := allowed.checkTLSVerify(true); err != nil {
		t.Errorf("allowed: %v", err)
	}
}

// TestDirectoryWithoutTLSRefused checks that outside development a connection
// without TLS is refused when saved and never dialled.
func TestDirectoryWithoutTLSRefused(t *testing.T) {
	ctx := context.Background()
	for _, test := range []struct {
		url       string
		startTLS  bool
		encrypted bool
	}{
		{"ldaps://ad.example.org:636", false, true},
		{"LDAPS://ad.example.org", false, true},
		{"ldap://ad.example.org:389", true, true},
		{"ldap://ad.example.org:389", false, false},
		{"LDAP://ad.example.org", false, false},
		{"not a url", true, false},
	} {
		if got := encrypted(test.url, test.startTLS); got != test.encrypted {
			t.Errorf("encrypted(%q, StartTLS %v) = %v, want %v", test.url, test.startTLS, got, test.encrypted)
		}
	}

	svc := unitService(t, production)
	_, err := svc.Create(ctx, uuid.New(), CreateInput{ServerURL: "ldap://ad.example.org:389"}, audit.Actor{})
	if !errors.Is(err, ErrTLSRequired) || errs.As(err).Code != CodeTLSRequired || errs.As(err).Message != "Use ldaps:// or turn on StartTLS." {
		t.Errorf("create without TLS: %v, want %s with its message", err, CodeTLSRequired)
	}
	plain := &connFull{Connection: Connection{ServerURL: "ldap://127.0.0.1:1"}, BindPassword: "secret"}
	if _, err := plain.dial(ctx, egress.DevelopmentPolicy(), false); !errors.Is(err, ErrTLSRequired) {
		t.Errorf("dial without TLS: %v, want %v before anything is sent", err, ErrTLSRequired)
	}
	if _, err := svc.authenticate(ctx, plain, "alice", "secret"); !errors.Is(err, ErrTLSRequired) {
		t.Errorf("sign-in bind without TLS: %v, want %v", err, ErrTLSRequired)
	}
	if err := unitService(t).checkTransport(plain.ServerURL, false); err != nil {
		t.Errorf("without TLS on a developer workstation: %v", err)
	}
}
