//go:build integration

package passkey

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// signUp runs a passkey sign-up for email over srv, as a browser would: begin,
// then answer with a new passkey on a virtual authenticator. It returns each
// step's status and body (no finish when begin is refused).
func signUp(t *testing.T, srv http.Handler, email string) (beginStatus int, begin string, finishStatus int, finish string) {
	t.Helper()
	rec := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/begin", map[string]any{"email": email})
	if rec.Code != http.StatusOK {
		return rec.Code, rec.Body.String(), 0, ""
	}
	var started struct {
		SessionID uuid.UUID       `json:"session_id"`
		PublicKey json.RawMessage `json:"publicKey"`
	}
	dbtest.Decode(t, rec, &started)
	options, err := virtualwebauthn.ParseAttestationOptions(`{"publicKey":` + string(started.PublicKey) + `}`)
	if err != nil {
		t.Fatalf("sign-up options: %v", err)
	}
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: []byte(options.UserID)})
	response := virtualwebauthn.CreateAttestationResponse(testRP, authenticator, virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2), *options)
	done := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/finish", map[string]any{
		"session_id": started.SessionID, "credential": json.RawMessage(response), "name": "Laptop",
	})
	return rec.Code, "", done.Code, done.Body.String()
}

// TestPasskeySignupBeginAnswersAlikeForATakenAddress checks that starting a
// passkey sign-up answers the same for a free address, one that already has
// an account and one on a domain an organization manages, and claims nothing,
// so a second start for the same address works; the taken and managed ones are
// refused when the ceremony finishes, with the same neutral answer and no
// account created, and the free one signs up.
func TestPasskeySignupBeginAnswersAlikeForATakenAddress(t *testing.T) {
	h := &Handler{Service: signInService(t)}
	srv := chi.NewRouter()
	h.MountPublic(srv)
	free := dbtest.Unique("free") + "@example.test"
	taken := dbtest.User(t, uuid.Nil).Email
	managed := dbtest.Unique("x") + "@" + dbtest.Domain(t, dbtest.Organization(t))

	if rec := dbtest.Do(t, srv, http.MethodPost, "/signup/passkey/begin", map[string]any{"email": free}); rec.Code != http.StatusOK {
		t.Fatalf("begin for a free address: %d %s", rec.Code, rec.Body.String())
	}
	refusals := map[string]string{}
	for name, email := range map[string]string{"a taken address": taken, "an address on a managed domain": managed, "a free address begun twice": free} {
		beginStatus, begin, finishStatus, finish := signUp(t, srv, email)
		if beginStatus != http.StatusOK {
			t.Errorf("begin for %s: %d %s, want 200 with options", name, beginStatus, begin)
			continue
		}
		if email == free {
			if finishStatus != http.StatusCreated {
				t.Errorf("finish for %s: %d %s, want 201", name, finishStatus, finish)
			}
			continue
		}
		var got struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(finish), &got); err != nil || finishStatus != http.StatusUnprocessableEntity || got.Error.Code != errs.CodeUnprocessable {
			t.Errorf("finish for %s: %d %s, want 422 %s", name, finishStatus, finish, errs.CodeUnprocessable)
		}
		refusals[name] = got.Error.Message
	}
	if refusals["a taken address"] != refusals["an address on a managed domain"] {
		t.Errorf("the refusals differ: %q and %q", refusals["a taken address"], refusals["an address on a managed domain"])
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE lower(email) = lower($1)`, managed); n != 0 {
		t.Errorf("%d accounts created on a managed domain, want none", n)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM account.users WHERE lower(email) = lower($1)`, taken); n != 1 {
		t.Errorf("%d accounts hold the taken address, want its own one", n)
	}
}
