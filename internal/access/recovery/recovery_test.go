package recovery

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestNewServiceNeedsItsDependencies checks that the recovery service can't
// be built without its sender, password rules, magic-link policy, domain
// capture, session signals or any of its request limits.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	full := Deps{
		Sender: stubSender{}, Rules: stubRules{}, MagicLinks: stubMagicLinks{}, Capture: stubCapture{},
		Signals: sessionsignal.New(nil), MagicPerAddress: stubLimit{}, MagicPerCaller: stubLimit{}, ResetPerAddress: stubLimit{},
	}
	for name, drop := range map[string]func(*Deps){
		"sender":                       func(d *Deps) { d.Sender = nil },
		"password rules":               func(d *Deps) { d.Rules = nil },
		"magic-link policy":            func(d *Deps) { d.MagicLinks = nil },
		"domain capture":               func(d *Deps) { d.Capture = nil },
		"session signals":              func(d *Deps) { d.Signals = nil },
		"magic-link limit per address": func(d *Deps) { d.MagicPerAddress = nil },
		"magic-link limit per caller":  func(d *Deps) { d.MagicPerCaller = nil },
		"reset limit per address":      func(d *Deps) { d.ResetPerAddress = nil },
	} {
		d := full
		drop(&d)
		if svc, err := NewService(&pgxpool.Pool{}, d); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("NewService without its %s: %v, %v; want an error naming it", name, svc, err)
		}
	}
	if _, err := NewService(&pgxpool.Pool{}, full); err != nil {
		t.Errorf("NewService with every dependency: %v", err)
	}
}

type (
	stubSender     struct{ notifier.Sender }
	stubRules      struct{ authpolicy.PasswordRules }
	stubMagicLinks struct{}
	stubCapture    struct{ auth.DomainCapture }
	stubLimit      struct{}
)

func (stubLimit) Take(context.Context, string) (bool, int) { return true, 0 }

func (stubMagicLinks) MagicLinkPolicy(context.Context, uuid.UUID) (bool, time.Duration, error) {
	return true, 0, nil
}
