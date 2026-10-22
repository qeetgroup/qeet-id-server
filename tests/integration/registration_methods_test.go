//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	passkey "github.com/qeetgroup/qeet-id-server/internal/access/passkeys"
	invite "github.com/qeetgroup/qeet-id-server/internal/identity/invitations"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestRegistrationRefusesAMethodTheOrganisationSwitchedOff: an organisation
// can switch password or passkey sign-in off, but hosted self-registration
// still made a password account where passwords were off and signed the person
// straight in, passkey registration still enrolled a passkey where passkeys
// were off, and an invitation could still be accepted with a password. Each is
// now refused with the answer sign-in gives for that method, before anything
// is created (a passkey ceremony doesn't even start); where the method is
// allowed, registration works as before.
func TestRegistrationRefusesAMethodTheOrganisationSwitchedOff(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	f := newInvitePasskeyFixture(t, ctx)
	setSelfRegistration(t, ctx, f.tenantID, true)
	authSvc, _ := newAuth()
	router := chi.NewRouter()
	router.Route("/v1", func(r chi.Router) {
		(&auth.Handler{Service: authSvc, Validate: validator.New()}).Mount(r)
		(&passkey.Handler{Service: f.passkeys}).MountPublic(r)
		(&invite.Handler{Service: f.invites, AuthService: authSvc, Validate: validator.New()}).MountPublic(r)
	})
	post := func(path string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) Chrome/154")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}
	accounts := func(t *testing.T, email string) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM "user".users WHERE lower(email) = lower($1)`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	ceremonies := func(t *testing.T, email string) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM auth.webauthn_sessions WHERE lower(pending_email) = lower($1)`, email).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rp := virtualwebauthn.RelyingParty{Name: pkRPName, ID: pkRPID, Origin: pkRPOrigin}
	// beginPasskey starts a hosted passkey registration and returns its
	// session and an authenticator's answer.
	beginPasskey := func(t *testing.T, email string) (*httptest.ResponseRecorder, uuid.UUID, json.RawMessage) {
		t.Helper()
		rr := post("/v1/register/passkey/begin", map[string]string{"tenant_id": f.tenantID.String(), "email": email})
		if rr.Code != http.StatusOK {
			return rr, uuid.Nil, nil
		}
		var begun struct {
			SessionID uuid.UUID       `json:"session_id"`
			PublicKey json.RawMessage `json:"publicKey"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &begun); err != nil {
			t.Fatal(err)
		}
		creation, _ := json.Marshal(map[string]json.RawMessage{"publicKey": begun.PublicKey})
		opts, err := virtualwebauthn.ParseAttestationOptions(string(creation))
		if err != nil {
			t.Fatal(err)
		}
		a := virtualwebauthn.NewAuthenticator()
		a.Options.UserHandle = []byte(opts.UserID)
		return rr, begun.SessionID, json.RawMessage(virtualwebauthn.CreateAttestationResponse(rp, a, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *opts))
	}
	finishPasskey := func(sid uuid.UUID, attestation json.RawMessage) *httptest.ResponseRecorder {
		return post("/v1/register/passkey/finish", map[string]any{"session_id": sid, "credential": attestation, "name": "Laptop"})
	}
	refusedAs := func(t *testing.T, what string, rr *httptest.ResponseRecorder, code string) {
		t.Helper()
		if rr.Code != http.StatusForbidden || errorCode(t, rr) != code || setsCookie(rr, auth.LoginSessionCookie) {
			t.Fatalf("%s = %d %s, want 403 %s and no cookie", what, rr.Code, rr.Body.String(), code)
		}
	}

	t.Run("passwords off: a password registration or invitation acceptance is refused and nothing is made", func(t *testing.T) {
		setSignInMethods(t, ctx, f.tenantID, false, true, true, 15)
		email := uniqueSlug("joiner") + "@example.com"
		refusedAs(t, "password registration", post("/v1/auth/register", map[string]string{
			"tenant_id": f.tenantID.String(), "email": email, "password": factorPassword,
		}), errs.CodeAuthMethodDisabled)
		if n := accounts(t, email); n != 0 {
			t.Fatalf("%d accounts made", n)
		}
		invited, token, _ := f.invite(t, ctx)
		refusedAs(t, "invitation accepted with a password", post("/v1/invites/accept", map[string]string{
			"token": token, "password": factorPassword,
		}), errs.CodeAuthMethodDisabled)
		if n := accounts(t, invited); n != 0 {
			t.Fatalf("%d accounts made for the invitation", n)
		}
	})

	t.Run("passkeys off: passkey registration is refused before a ceremony starts", func(t *testing.T) {
		setSignInMethods(t, ctx, f.tenantID, true, false, true, 15)
		email := uniqueSlug("pk-joiner") + "@example.com"
		rr, _, _ := beginPasskey(t, email)
		refusedAs(t, "passkey registration begin", rr, errs.CodePasskeyDisabled)
		if n := ceremonies(t, email); n != 0 {
			t.Fatalf("%d ceremonies started", n)
		}

		// A ceremony begun while passkeys were on, finished after they were
		// switched off, makes nothing either.
		setSignInMethods(t, ctx, f.tenantID, true, true, true, 15)
		late := uniqueSlug("pk-late") + "@example.com"
		_, sid, attestation := beginPasskey(t, late)
		setSignInMethods(t, ctx, f.tenantID, true, false, true, 15)
		refusedAs(t, "passkey registration finished after the switch", finishPasskey(sid, attestation), errs.CodePasskeyDisabled)
		if n := accounts(t, late); n != 0 {
			t.Fatalf("%d accounts made", n)
		}
	})

	t.Run("methods allowed: registration works as before", func(t *testing.T) {
		setSignInMethods(t, ctx, f.tenantID, true, true, true, 15)
		email := uniqueSlug("joiner-ok") + "@example.com"
		if rr := post("/v1/auth/register", map[string]string{"tenant_id": f.tenantID.String(), "email": email, "password": factorPassword}); rr.Code != http.StatusCreated || !setsCookie(rr, auth.LoginSessionCookie) {
			t.Fatalf("password registration = %d %s, want 201 and the cookie", rr.Code, rr.Body.String())
		}
		pkEmail := uniqueSlug("pk-joiner-ok") + "@example.com"
		rr, sid, attestation := beginPasskey(t, pkEmail)
		if rr.Code != http.StatusOK {
			t.Fatalf("passkey registration begin = %d %s", rr.Code, rr.Body.String())
		}
		if rr := finishPasskey(sid, attestation); rr.Code != http.StatusCreated || !setsCookie(rr, auth.LoginSessionCookie) {
			t.Fatalf("passkey registration finish = %d %s, want 201 and the cookie", rr.Code, rr.Body.String())
		}
		_, token, _ := f.invite(t, ctx)
		if rr := post("/v1/invites/accept", map[string]string{"token": token, "password": factorPassword}); rr.Code != http.StatusOK && rr.Code != http.StatusCreated {
			t.Fatalf("invitation accepted with a password = %d %s", rr.Code, rr.Body.String())
		}
	})
}
