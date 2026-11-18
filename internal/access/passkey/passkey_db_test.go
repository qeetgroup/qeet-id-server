//go:build integration

package passkey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth/authtest"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

// newService returns the passkey service for the relying party example.test,
// issuing sessions, in organizations that allow passkeys, with no invitation
// to accept and no address captured. Each change applies to its Deps first.
func newService(t *testing.T, change ...func(*Deps)) *Service {
	t.Helper()
	pool := dbtest.Pool(t)
	d := Deps{
		RelyingParty: relyingParty(t), Auth: authtest.New(t, pool), Policy: allowPasskeys{},
		Invitations: noInvitations{}, Sender: &dbtest.Mailbox{}, Capture: noCapture{},
	}
	for _, c := range change {
		c(&d)
	}
	svc, err := NewService(d)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// relyingParty returns the relying party example.test.
func relyingParty(t *testing.T) *RelyingParty {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{
		RPID: "example.test", RPDisplayName: "Qeet ID", RPOrigins: []string{"https://example.test"},
	})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	rp, err := NewRelyingParty(dbtest.Pool(t), wa)
	if err != nil {
		t.Fatal(err)
	}
	return rp
}

// allowPasskeys lets every organization use passkeys.
type allowPasskeys struct{}

func (allowPasskeys) PasskeyEnabled(context.Context, uuid.UUID) (bool, error) { return true, nil }

// noCapture captures no address.
type noCapture struct{}

func (noCapture) RefuseCaptured(context.Context, string) error { return nil }

// noInvitations knows no invitation.
type noInvitations struct{ InvitationAcceptor }

func (noInvitations) InvitationForNewAccount(context.Context, string) (uuid.UUID, uuid.UUID, string, error) {
	return uuid.Nil, uuid.Nil, "", errs.ErrNotImplemented
}

// captureDomain refuses every address on its domain, as an organization that
// requires single sign-on there does.
type captureDomain string

func (d captureDomain) RefuseCaptured(_ context.Context, email string) error {
	if strings.HasSuffix(strings.ToLower(email), "@"+string(d)) {
		return errs.ErrAuthSSORequired
	}
	return nil
}

// TestCapturedAddressesUseNoPasskey checks that an account on a captured
// domain can't sign in with its passkey, whether the ceremony names its
// address or not, that no passkey sign-up starts for an address there, and
// that other accounts' passkeys sign in as before.
func TestCapturedAddressesUseNoPasskey(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := signInService(t)
	organization := dbtest.Organization(t)
	domain := dbtest.Unique("acme") + ".example.test"
	captured := dbtest.UserAt(t, dbtest.Unique("asha")+"@"+domain, organization, organization)
	free := dbtest.User(t, organization, organization)
	d, other := register(t, svc, captured.ID, "Laptop"), register(t, svc, free.ID, "Phone")
	svc.capture = captureDomain(domain)

	if _, _, err := svc.BeginLogin(ctx, strings.ToUpper(captured.Email)); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("begin a sign-in naming a captured address: %v, want %v", err, errs.ErrAuthSSORequired)
	}
	sessionID, response := d.assert(t, svc, "", testRP)
	if _, err := svc.FinishLogin(ctx, sessionID, response, "192.0.2.1", "test"); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("a discoverable sign-in with a captured account's passkey: %v, want %v", err, errs.ErrAuthSSORequired)
	}
	sessionID, response = d.assert(t, svc, "", testRP)
	if _, _, err := svc.FinishLoginSession(ctx, sessionID, response, "192.0.2.1", "test"); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("a hosted sign-in with a captured account's passkey: %v, want %v", err, errs.ErrAuthSSORequired)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM auth.sessions WHERE user_id = $1`, captured.ID); n != 0 {
		t.Errorf("a captured account's passkey opened %d sessions", n)
	}
	if _, _, err := svc.BeginSignup(ctx, dbtest.Unique("nobody")+"@"+domain, ""); !errors.Is(err, errs.ErrAuthSSORequired) {
		t.Errorf("begin a passkey sign-up on a captured domain: %v, want %v", err, errs.ErrAuthSSORequired)
	}

	sessionID, response = other.assert(t, svc, free.Email, testRP)
	if pair, err := svc.FinishLogin(ctx, sessionID, response, "192.0.2.1", "test"); err != nil || pair.UserID != free.ID {
		t.Errorf("a passkey of an account on no captured domain: %+v, %v", pair, err)
	}
}

// noPasskeys is an organization policy that turns passkeys off.
type noPasskeys struct{}

func (noPasskeys) PasskeyEnabled(context.Context, uuid.UUID) (bool, error) { return false, nil }

// TestPasskeysOffForTheOrganization checks that a passkey can't be registered
// where the account's organization turned passkeys off.
func TestPasskeysOffForTheOrganization(t *testing.T) {
	svc := signInService(t)
	svc.policy = noPasskeys{}
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	if _, _, err := svc.BeginRegister(dbtest.Context(t), a.ID); !errors.Is(err, ErrDisabled) {
		t.Errorf("register where passkeys are off: %v, want %v", err, ErrDisabled)
	}
}
