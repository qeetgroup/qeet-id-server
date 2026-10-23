//go:build integration

package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// testRP is the relying party the tests' passkeys are made for.
var testRP = virtualwebauthn.RelyingParty{ID: "example.test", Name: "Qeet ID", Origin: "https://example.test"}

// signInService returns the passkey service for testRP, issuing sessions.
func signInService(t *testing.T) *Service {
	t.Helper()
	wa, err := webauthn.New(&webauthn.Config{RPID: testRP.ID, RPDisplayName: testRP.Name, RPOrigins: []string{testRP.Origin}})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	pool := dbtest.Pool(t)
	return NewService(pool, wa, auth.NewService(pool, user.NewRepository(pool), dbtest.Issuer(t)))
}

// device is a virtual authenticator holding one passkey.
type device struct {
	authenticator virtualwebauthn.Authenticator
	credential    virtualwebauthn.Credential
}

// register creates a passkey for userID on a new virtual authenticator.
func register(t *testing.T, svc *Service, userID uuid.UUID, name string) *device {
	t.Helper()
	ctx := dbtest.Context(t)
	sessionID, creation, err := svc.BeginRegister(ctx, userID)
	if err != nil {
		t.Fatalf("begin registration: %v", err)
	}
	raw, _ := json.Marshal(creation)
	options, err := virtualwebauthn.ParseAttestationOptions(string(raw))
	if err != nil {
		t.Fatalf("registration options: %v", err)
	}
	d := &device{
		authenticator: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(options.UserID)}),
		credential:    virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	response := virtualwebauthn.CreateAttestationResponse(testRP, d.authenticator, d.credential, *options)
	if err := svc.FinishRegister(ctx, userID, sessionID, json.RawMessage(response), name, ""); err != nil {
		t.Fatalf("finish registration: %v", err)
	}
	d.authenticator.AddCredential(d.credential)
	return d
}

// assert answers the sign-in started for email, as rp sees it.
func (d *device) assert(t *testing.T, svc *Service, email string, rp virtualwebauthn.RelyingParty) (uuid.UUID, json.RawMessage) {
	t.Helper()
	sessionID, assertion, err := svc.BeginLogin(dbtest.Context(t), email)
	if err != nil {
		t.Fatalf("begin sign-in: %v", err)
	}
	raw, _ := json.Marshal(assertion)
	options, err := virtualwebauthn.ParseAssertionOptions(string(raw))
	if err != nil {
		t.Fatalf("sign-in options: %v", err)
	}
	return sessionID, json.RawMessage(virtualwebauthn.CreateAssertionResponse(rp, d.authenticator, d.credential, *options))
}

// TestPasskeyRegistersAndSignsIn checks that a registered passkey signs its
// account in, once per ceremony and only for this site, is listed and renamed,
// and can't be removed while it is the account's only way to sign in.
func TestPasskeyRegistersAndSignsIn(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := signInService(t)
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	d := register(t, svc, a.ID, "Laptop")

	creds, err := svc.List(ctx, a.ID)
	if err != nil || len(creds) != 1 || creds[0].Name == nil || *creds[0].Name != "Laptop" {
		t.Fatalf("passkeys %+v, %v; want the one named Laptop", creds, err)
	}

	sessionID, response := d.assert(t, svc, a.Email, testRP)
	pair, err := svc.FinishLogin(ctx, sessionID, response, "192.0.2.1", "test")
	if err != nil || pair == nil || pair.UserID != a.ID {
		t.Fatalf("sign in with the passkey: %+v, %v", pair, err)
	}
	if _, err := svc.FinishLogin(ctx, sessionID, response, "192.0.2.1", "test"); err == nil {
		t.Error("the same sign-in answer was accepted twice")
	}
	elsewhere := testRP
	elsewhere.Origin = "https://phishing.test"
	sessionID, response = d.assert(t, svc, a.Email, elsewhere)
	if _, err := svc.FinishLogin(ctx, sessionID, response, "192.0.2.1", "test"); err == nil {
		t.Error("an answer made for another site signed in")
	}

	if renamed, err := svc.Rename(ctx, creds[0].ID, a.ID, "Work laptop"); err != nil || renamed.Name == nil || *renamed.Name != "Work laptop" {
		t.Errorf("rename: %+v, %v", renamed, err)
	}
	if err := svc.Delete(ctx, creds[0].ID, a.ID, user.Remover{UserID: &a.ID}); !errors.Is(err, errs.ErrAuthLastSignInMethod) {
		t.Errorf("remove the only way to sign in: %v, want %v", err, errs.ErrAuthLastSignInMethod)
	}
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	if err := svc.Delete(ctx, creds[0].ID, a.ID, user.Remover{UserID: &a.ID}); err != nil {
		t.Errorf("remove a passkey beside a password: %v", err)
	}
}

// noPasskeys is an organisation policy that turns passkeys off.
type noPasskeys struct{}

func (noPasskeys) PasskeyEnabled(context.Context, uuid.UUID) (bool, error) { return false, nil }

// TestPasskeysOffForTheOrganisation checks that a passkey can't be registered
// where the account's organisation turned passkeys off.
func TestPasskeysOffForTheOrganisation(t *testing.T) {
	svc := signInService(t)
	svc.SetMethodPolicy(noPasskeys{})
	tenant := dbtest.Tenant(t)
	a := dbtest.User(t, tenant, tenant)
	if _, _, err := svc.BeginRegister(dbtest.Context(t), a.ID); !errors.Is(err, errs.ErrPasskeyDisabled) {
		t.Errorf("register where passkeys are off: %v, want %v", err, errs.ErrPasskeyDisabled)
	}
}
