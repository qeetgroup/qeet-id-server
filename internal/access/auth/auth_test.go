package auth

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/ipallow"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/envelope"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// TestNewRefusesAMissingDependency checks that the sign-in service can't be
// built without a dependency a sign-in check needs, naming the one missing,
// so a server wired without it does not start. Without MFA a password
// sign-in would skip the second factor; without Risk no sign-in is assessed.
func TestNewRefusesAMissingDependency(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop func(*Deps)
	}{
		{"MFA", func(d *Deps) { d.MFA = nil }},
		{"Risk", func(d *Deps) { d.Risk = nil }},
		{"Pool", func(d *Deps) { d.Pool = nil }},
		{"Users", func(d *Deps) { d.Users = nil }},
		{"Tokens", func(d *Deps) { d.Tokens = nil }},
		{"Cipher", func(d *Deps) { d.Cipher = nil }},
		{"Registration", func(d *Deps) { d.Registration = nil }},
		{"Methods", func(d *Deps) { d.Methods = nil }},
		{"Devices", func(d *Deps) { d.Devices = nil }},
		{"Lockout", func(d *Deps) { d.Lockout = nil }},
		{"Capture", func(d *Deps) { d.Capture = nil }},
		{"Addresses", func(d *Deps) { d.Addresses = nil }},
		{"Anomalies", func(d *Deps) { d.Anomalies = nil }},
		{"Sender", func(d *Deps) { d.Sender = nil }},
		{"LoginHook", func(d *Deps) { d.LoginHook = nil }},
		{"SignOut", func(d *Deps) { d.SignOut = nil }},
		{"Signals", func(d *Deps) { d.Signals = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := completeDeps()
			tc.drop(&d)
			if svc, err := New(d); err == nil || !strings.Contains(err.Error(), tc.name) {
				t.Fatalf("New without %s: %v, %v; want an error naming it", tc.name, svc, err)
			}
		})
	}
	if svc, err := New(completeDeps()); err != nil || svc == nil {
		t.Fatalf("New with every dependency: %v, %v", svc, err)
	}
}

// completeDeps returns Deps with every dependency set, none of them called.
func completeDeps() Deps {
	return Deps{
		Pool: &pgxpool.Pool{}, Users: &user.Repository{}, Tokens: &tokens.Issuer{}, Cipher: &envelope.Cipher{},
		MFA: stubMFA{}, Risk: stubRisk{}, Registration: stubPolicy{}, Methods: stubPolicy{}, Devices: stubPolicy{},
		Lockout:   func(context.Context, uuid.UUID) (Lockout, error) { return Lockout{}, nil },
		Capture:   stubCapture{},
		Addresses: stubAddresses{},
		Anomalies: stubAnomalies{},
		Sender:    stubSender{},
		LoginHook: stubHook{},
		SignOut:   stubSignOut{},
		Signals:   sessionsignal.New(nil),
	}
}

type (
	stubMFA       struct{ MFAEnroller }
	stubRisk      struct{ RiskAssessor }
	stubCapture   struct{ DomainCapture }
	stubAddresses struct{ ipallow.AddressPolicy }
	stubAnomalies struct{ AnomalyRecorder }
	stubSender    struct{ notifier.Sender }
	stubHook      struct{ LoginHook }
	stubSignOut   struct{ SignOutNotifier }
	stubPolicy    struct {
		RegistrationPolicy
		MethodPolicy
		DevicePolicy
	}
)
