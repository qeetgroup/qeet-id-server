package ldap

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
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
	svc := unitService(t)
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

	allowed := unitService(t, func(d *Deps) { d.AllowSkipTLSVerify = true })
	if err := allowed.checkTLSVerify(true); err != nil {
		t.Errorf("allowed: %v", err)
	}
}
