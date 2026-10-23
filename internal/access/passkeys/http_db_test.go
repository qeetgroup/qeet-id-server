//go:build integration

package passkey

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// send posts body to h with cookies, failing t unless it answers want.
func send(t *testing.T, h http.Handler, method, path string, body any, cookies []*http.Cookie, want int) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequestWithContext(dbtest.Context(t), method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != want {
		t.Fatalf("%s %s: %d %s, want %d", method, path, rec.Code, rec.Body.String(), want)
	}
	return rec
}

// ceremony is a begin answer: its session and its options as JSON.
type ceremony struct {
	SessionID uuid.UUID       `json:"session_id"`
	PublicKey json.RawMessage `json:"publicKey"`
}

func begun(t *testing.T, rec *httptest.ResponseRecorder) ceremony {
	t.Helper()
	var c ceremony
	dbtest.Decode(t, rec, &c)
	return c
}

// attest makes a passkey on a new virtual authenticator for c.
func attest(t *testing.T, c ceremony) (*device, json.RawMessage) {
	t.Helper()
	options, err := virtualwebauthn.ParseAttestationOptions(string(c.PublicKey))
	if err != nil {
		t.Fatalf("registration options: %v", err)
	}
	d := &device{
		authenticator: virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(options.UserID)}),
		credential:    virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
	}
	response := virtualwebauthn.CreateAttestationResponse(testRP, d.authenticator, d.credential, *options)
	d.authenticator.AddCredential(d.credential)
	return d, json.RawMessage(response)
}

// TestPasskeysOverHTTP checks the passkey API end to end: signing up with a
// passkey, listing, renaming, adding and removing passkeys while signed in,
// and signing in with one.
func TestPasskeysOverHTTP(t *testing.T) {
	svc := signInService(t)
	h := &Handler{Service: svc}
	public := chi.NewRouter()
	h.MountPublic(public)
	email := dbtest.Unique("passkey") + "@example.test"

	signup := begun(t, send(t, public, http.MethodPost, "/signup/passkey/begin", map[string]string{"email": email, "display_name": "Pat"}, nil, http.StatusOK))
	first, credential := attest(t, signup)
	rec := send(t, public, http.MethodPost, "/signup/passkey/finish", map[string]any{"session_id": signup.SessionID, "credential": credential, "name": "Laptop"}, nil, http.StatusCreated)
	var created struct {
		UserID      uuid.UUID `json:"user_id"`
		AccessToken string    `json:"access_token"`
	}
	dbtest.Decode(t, rec, &created)
	if created.UserID == uuid.Nil || created.AccessToken == "" {
		t.Fatalf("signup: %s; want the new account signed in", rec.Body.String())
	}

	signedIn := dbtest.Serve(dbtest.Principal(created.UserID, uuid.Nil), h.Mount)
	register := begun(t, send(t, signedIn, http.MethodPost, "/passkeys/register/begin", nil, nil, http.StatusOK))
	_, second := attest(t, register)
	send(t, signedIn, http.MethodPost, "/passkeys/register/finish", map[string]any{"session_id": register.SessionID, "credential": second, "name": "Phone"}, nil, http.StatusNoContent)
	var list struct {
		Items []Credential `json:"items"`
	}
	dbtest.Decode(t, send(t, signedIn, http.MethodGet, "/passkeys", nil, nil, http.StatusOK), &list)
	if len(list.Items) != 2 {
		t.Fatalf("passkeys %+v, want two", list.Items)
	}
	phone := list.Items[0].ID
	for _, c := range list.Items {
		if c.Name != nil && *c.Name == "Phone" {
			phone = c.ID
		}
	}
	send(t, signedIn, http.MethodPatch, "/passkeys/"+phone.String(), map[string]string{"name": "Old phone"}, nil, http.StatusOK)
	send(t, signedIn, http.MethodDelete, "/passkeys/"+phone.String(), nil, nil, http.StatusNoContent)

	login := send(t, public, http.MethodPost, "/passkeys/login/begin", map[string]string{"email": email}, nil, http.StatusOK)
	challenge := begun(t, login)
	options, err := virtualwebauthn.ParseAssertionOptions(string(challenge.PublicKey))
	if err != nil {
		t.Fatalf("sign-in options: %v", err)
	}
	assertion := virtualwebauthn.CreateAssertionResponse(testRP, first.authenticator, first.credential, *options)
	rec = send(t, public, http.MethodPost, "/passkeys/login/finish", map[string]any{"session_id": challenge.SessionID, "credential": json.RawMessage(assertion)}, login.Result().Cookies(), http.StatusOK)
	var pair struct {
		AccessToken string `json:"access_token"`
	}
	dbtest.Decode(t, rec, &pair)
	if pair.AccessToken == "" {
		t.Errorf("sign in with the passkey: %s", rec.Body.String())
	}
}
