package mfa

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestNewServiceNeedsItsDependencies checks that the second-factor service
// can't be built without its sender, cipher, plan gate, delivery check or
// passkey verifier, nor with a push setting that can't work.
func TestNewServiceNeedsItsDependencies(t *testing.T) {
	full := Deps{
		Issuer: "Qeet", Sender: stubSender{}, Cipher: &envelope.Cipher{}, Plan: stubGate{},
		Deliverable: func(string) bool { return true }, WebAuthn: stubWebAuthn{},
	}
	for name, change := range map[string]func(*Deps){
		"Sender":      func(d *Deps) { d.Sender = nil },
		"Cipher":      func(d *Deps) { d.Cipher = nil },
		"Plan":        func(d *Deps) { d.Plan = nil },
		"Deliverable": func(d *Deps) { d.Deliverable = nil },
		"WebAuthn":    func(d *Deps) { d.WebAuthn = nil },
		"APNs":        func(d *Deps) { d.APNs = &APNsConfig{AuthKey: "not a key", KeyID: "K", TeamID: "T", BundleID: "B"} },
		"FCM":         func(d *Deps) { d.FCM = &FCMConfig{ServiceAccountJSON: `{"project_id":"p"}`} },
	} {
		d := full
		change(&d)
		if svc, err := NewService(&pgxpool.Pool{}, d); err == nil {
			t.Errorf("NewService with a bad %s: %v, nil; want an error", name, svc)
		}
	}
	if _, err := NewService(&pgxpool.Pool{}, full); err != nil {
		t.Errorf("NewService with every dependency: %v", err)
	}
}

type (
	stubSender   struct{ notifier.Sender }
	stubGate     struct{ entitlements.PlanGate }
	stubWebAuthn struct{ WebAuthnVerifier }
)
