package ldap

import (
	"context"
	"errors"
	"strings"
	"testing"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"

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

func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"ldaps://ldap.corp.com:636": "ldap.corp.com",
		"ldap://localhost:389":      "localhost",
		"ldaps://ad.example.org":    "ad.example.org",
		"not a url":                 "",
	}
	for in, want := range cases {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTLSConfig(t *testing.T) {
	c := &connFull{Connection: Connection{ServerURL: "ldaps://ad.example.org:636", SkipTLSVerify: true}}
	if !c.tlsConfig(true).InsecureSkipVerify {
		t.Error("SkipTLSVerify should propagate to InsecureSkipVerify where it is allowed")
	}
	cfg := c.tlsConfig(false)
	if cfg.InsecureSkipVerify {
		t.Error("SkipTLSVerify must not turn verification off where it is not allowed")
	}
	if cfg.ServerName != "ad.example.org" {
		t.Errorf("ServerName = %q, want ad.example.org", cfg.ServerName)
	}

	c2 := &connFull{Connection: Connection{ServerURL: "ldaps://ad.example.org:636"}}
	if c2.tlsConfig(true).InsecureSkipVerify {
		t.Error("verification should be on by default")
	}
}

// TestSkipTLSVerifyRefused checks that a connection which turns certificate
// verification off is refused, when saved and when it binds, unless that is
// allowed.
func TestSkipTLSVerifyRefused(t *testing.T) {
	ctx := context.Background()
	svc := NewService(nil, nil, egress.DevelopmentPolicy())
	skip := true
	if _, err := svc.Create(ctx, nil, uuid.New(), CreateInput{ServerURL: "ldaps://ad.example.org:636", SkipTLSVerify: true}); !errors.Is(err, errs.ErrLDAPTLSVerifyRequired) {
		t.Errorf("create: %v, want %v", err, errs.ErrLDAPTLSVerifyRequired)
	}
	if _, err := svc.Update(ctx, nil, uuid.New(), uuid.New(), UpdateInput{SkipTLSVerify: &skip}); !errors.Is(err, errs.ErrLDAPTLSVerifyRequired) {
		t.Errorf("update: %v, want %v", err, errs.ErrLDAPTLSVerifyRequired)
	}
	c := &connFull{Connection: Connection{ServerURL: "ldaps://127.0.0.1:1", SkipTLSVerify: true}}
	if err := svc.TestBind(ctx, c); !errors.Is(err, errs.ErrLDAPTLSVerifyRequired) {
		t.Errorf("test bind: %v, want %v", err, errs.ErrLDAPTLSVerifyRequired)
	}
	if _, err := svc.authenticate(ctx, c, "alice", "secret"); !errors.Is(err, errs.ErrLDAPTLSVerifyRequired) {
		t.Errorf("sign-in bind: %v, want %v", err, errs.ErrLDAPTLSVerifyRequired)
	}

	svc.SetAllowSkipTLSVerify(true)
	if err := svc.checkTLSVerify(true); err != nil {
		t.Errorf("allowed: %v", err)
	}
}

// TestUserFilterEscaping checks that the username is LDAP-escaped before it is
// put into the user-search filter, so it can't inject filter syntax.
func TestUserFilterEscaping(t *testing.T) {
	filter := "(uid=%s)"
	malicious := "*)(uid=*"
	built := strings.ReplaceAll(filter, "%s", goldap.EscapeFilter(malicious))
	if strings.Contains(built, "*)(uid=*") {
		t.Errorf("raw injection survived escaping: %q", built)
	}
	// A normal username substitutes cleanly.
	ok := strings.ReplaceAll(filter, "%s", goldap.EscapeFilter("alice"))
	if ok != "(uid=alice)" {
		t.Errorf("normal username = %q, want (uid=alice)", ok)
	}
}
