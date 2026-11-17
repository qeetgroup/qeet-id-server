//go:build integration

package passkey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

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
	svc.SetDomainCapture(captureDomain(domain))

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
