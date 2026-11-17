//go:build integration

package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
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

// register creates a passkey for userID on a new virtual authenticator, asked
// for by userID with no organization.
func register(t *testing.T, svc *Service, userID uuid.UUID, name string) *device {
	t.Helper()
	return registerAs(t, svc, userID, name, Requester{Actor: audit.Actor{UserID: &userID, Type: "user"}})
}

// registerAs is register asked for by who.
func registerAs(t *testing.T, svc *Service, userID uuid.UUID, name string, who Requester) *device {
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
	if err := svc.FinishRegister(ctx, userID, sessionID, json.RawMessage(response), name, who); err != nil {
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
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
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

	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user"}}
	if renamed, err := svc.Rename(ctx, creds[0].ID, a.ID, "Work laptop", who); err != nil || renamed.Name == nil || *renamed.Name != "Work laptop" {
		t.Errorf("rename: %+v, %v", renamed, err)
	}
	if err := svc.Delete(ctx, creds[0].ID, a.ID, who); !errors.Is(err, errs.ErrAuthLastSignInMethod) {
		t.Errorf("remove the only way to sign in: %v, want %v", err, errs.ErrAuthLastSignInMethod)
	}
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	if err := svc.Delete(ctx, creds[0].ID, a.ID, who); err != nil {
		t.Errorf("remove a passkey beside a password: %v", err)
	}
}

// TestPasskeyChangesAreAuditedAndTold checks that adding, renaming and
// removing a passkey are each recorded in the organization the session is in,
// naming the passkey, and that the account holder is emailed when one is added
// or removed, but not when a removal is refused or another's passkey is asked
// for.
func TestPasskeyChangesAreAuditedAndTold(t *testing.T) {
	ctx := dbtest.Context(t)
	svc := signInService(t)
	mail := &dbtest.Mailbox{}
	svc.SetSender(mail)
	organization := dbtest.Organization(t)
	a, other := dbtest.User(t, organization, organization), dbtest.User(t, organization, organization)
	who := Requester{Actor: audit.Actor{UserID: &a.ID, Type: "user", IP: "192.0.2.7", RequestID: "req-passkey"}, OrganizationID: &organization}
	type record struct {
		PasskeyID    uuid.UUID `json:"passkey_id"`
		Name         string    `json:"name"`
		PreviousName string    `json:"previous_name"`
	}
	audited := func(action string) []record {
		t.Helper()
		rows, err := dbtest.Pool(t).Query(ctx, `
			SELECT metadata FROM audit.events
			WHERE organization_id = $1 AND action = $2 AND resource_type = 'user' AND resource_id = $3
			  AND actor_user_id = $3 AND ip = '192.0.2.7' AND request_id = 'req-passkey'
			ORDER BY created_at`, organization, action, a.ID)
		if err != nil {
			t.Fatalf("read audit: %v", err)
		}
		defer rows.Close()
		var out []record
		for rows.Next() {
			var raw []byte
			var r record
			if err := rows.Scan(&raw); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}

	registerAs(t, svc, a.ID, "Laptop", who)
	creds, err := svc.List(ctx, a.ID)
	if err != nil || len(creds) != 1 {
		t.Fatalf("passkeys %+v, %v; want one", creds, err)
	}
	id := creds[0].ID
	if got := audited("passkey.registered"); len(got) != 1 || got[0].PasskeyID != id || got[0].Name != "Laptop" {
		t.Errorf("passkey.registered records %+v, want one naming the Laptop passkey", got)
	}
	added := mail.Last(t)
	if added.To != a.Email || !strings.Contains(added.Subject, "added") || !strings.Contains(added.Body, "Laptop") || added.HTML == "" {
		t.Errorf("notice %+v, want one to %s that the Laptop passkey was added", added, a.Email)
	}

	if _, err := svc.Rename(ctx, id, a.ID, "Work laptop", who); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := audited("passkey.renamed"); len(got) != 1 || got[0].Name != "Work laptop" || got[0].PreviousName != "Laptop" {
		t.Errorf("passkey.renamed records %+v, want one from Laptop to Work laptop", got)
	}
	if _, err := svc.Rename(ctx, id, other.ID, "Mine now", who); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("rename another's passkey: %v, want %v", err, errs.ErrNotFound)
	}

	sent := mail.Len()
	if err := svc.Delete(ctx, id, a.ID, who); !errors.Is(err, errs.ErrAuthLastSignInMethod) {
		t.Fatalf("remove the only way to sign in: %v, want %v", err, errs.ErrAuthLastSignInMethod)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE organization_id = $1 AND action = 'auth.sign_in_method_removal_refused' AND resource_id = $2`, organization, a.ID); n != 1 {
		t.Errorf("%d refusals recorded in the organisation, want 1", n)
	}
	dbtest.SetPassword(t, a.ID, "Kx7mQ2vLp9Wz")
	if err := svc.Delete(ctx, id, other.ID, who); !errors.Is(err, errs.ErrNotFound) {
		t.Errorf("remove another's passkey: %v, want %v", err, errs.ErrNotFound)
	}
	if mail.Len() != sent {
		t.Error("a refused removal emailed the account holder")
	}
	if err := svc.Delete(ctx, id, a.ID, who); err != nil {
		t.Fatalf("remove a passkey beside a password: %v", err)
	}
	if got := audited("passkey.deleted"); len(got) != 1 || got[0].PasskeyID != id || got[0].Name != "Work laptop" {
		t.Errorf("passkey.deleted records %+v, want one naming the Work laptop passkey", got)
	}
	removed := mail.Last(t)
	if removed.To != a.Email || !strings.Contains(removed.Subject, "removed") || !strings.Contains(removed.Body, "Work laptop") {
		t.Errorf("notice %+v, want one to %s that the Work laptop passkey was removed", removed, a.Email)
	}
}

// noPasskeys is an organization policy that turns passkeys off.
type noPasskeys struct{}

func (noPasskeys) PasskeyEnabled(context.Context, uuid.UUID) (bool, error) { return false, nil }

// TestPasskeysOffForTheOrganization checks that a passkey can't be registered
// where the account's organization turned passkeys off.
func TestPasskeysOffForTheOrganization(t *testing.T) {
	svc := signInService(t)
	svc.SetMethodPolicy(noPasskeys{})
	organization := dbtest.Organization(t)
	a := dbtest.User(t, organization, organization)
	if _, _, err := svc.BeginRegister(dbtest.Context(t), a.ID); !errors.Is(err, errs.ErrPasskeyDisabled) {
		t.Errorf("register where passkeys are off: %v, want %v", err, errs.ErrPasskeyDisabled)
	}
}
