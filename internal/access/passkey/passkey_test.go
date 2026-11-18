package passkey

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestNewServiceNeedsItsDependencies checks that the passkey service can't be
// built without its relying party, the sign-in service, the passkey policy,
// invitations, its sender or domain capture, nor a relying party without its
// WebAuthn configuration.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	full := Deps{
		RelyingParty: &RelyingParty{}, Auth: &auth.Service{}, Policy: stubPolicy{}, Invitations: stubInvitations{},
		Sender: stubSender{}, Capture: stubCapture{},
	}
	for name, drop := range map[string]func(*Deps){
		"RelyingParty": func(d *Deps) { d.RelyingParty = nil },
		"Auth":         func(d *Deps) { d.Auth = nil },
		"Policy":       func(d *Deps) { d.Policy = nil },
		"Invitations":  func(d *Deps) { d.Invitations = nil },
		"Sender":       func(d *Deps) { d.Sender = nil },
		"Capture":      func(d *Deps) { d.Capture = nil },
	} {
		d := full
		drop(&d)
		if svc, err := NewService(d); err == nil {
			t.Errorf("NewService without %s: %v, nil; want an error", name, svc)
		}
	}
	if _, err := NewService(full); err != nil {
		t.Errorf("NewService with every dependency: %v", err)
	}
	if rp, err := NewRelyingParty(&pgxpool.Pool{}, nil); err == nil {
		t.Errorf("NewRelyingParty without a WebAuthn configuration: %v, nil; want an error", rp)
	}
}

type (
	stubPolicy      struct{ MethodPolicy }
	stubInvitations struct{ InvitationAcceptor }
	stubSender      struct{ notifier.Sender }
	stubCapture     struct{ auth.DomainCapture }
)
