package saml

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	samltypes "github.com/russellhaering/gosaml2/types"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
)

func TestTrustedCorrelationIgnoresUnsignedResponseEnvelope(t *testing.T) {
	response := &samltypes.Response{
		InResponseTo: "_forged-envelope-request",
		Assertions: []samltypes.Assertion{{
			ID:                 "_signed-assertion",
			SignatureValidated: true,
			Subject: &samltypes.Subject{SubjectConfirmation: &samltypes.SubjectConfirmation{
				SubjectConfirmationData: &samltypes.SubjectConfirmationData{InResponseTo: "_trusted-request"},
			}},
		}},
	}

	requestID, assertionIDs, err := trustedCorrelation(response)
	if err != nil {
		t.Fatalf("trustedCorrelation: %v", err)
	}
	if requestID != "_trusted-request" {
		t.Fatalf("request ID = %q, want signed assertion value", requestID)
	}
	if len(assertionIDs) != 1 || assertionIDs[0] != "_signed-assertion" {
		t.Fatalf("assertion IDs = %v, want signed assertion ID", assertionIDs)
	}
}

// TestAFailedHostedSignInGoesBackToTheHostedLogin checks that a sign-in the hosted login began
// returns there with a generic error and its way back to the application when it fails, and that
// one without a stored return address, or with no hosted login configured, gets the error itself.
func TestAFailedHostedSignInGoesBackToTheHostedLogin(t *testing.T) {
	const accounts = "https://accounts.example.test"
	back := "https://api.example.test/oauth/authorize?client_id=portal&state=s1"
	configured := newTestService(t, new(pgxpool.Pool), new(auth.Service), func(d *Deps) {
		d.LoginBaseURL, d.ReturnOrigins = accounts, []string{"https://api.example.test"}
	})
	for _, tc := range []struct {
		name     string
		service  *Service
		returnTo string
		want     int
	}{
		{"a hosted sign-in", configured, back, http.StatusFound},
		{"a console sign-in", configured, "", http.StatusBadRequest},
		{"no hosted login configured", newTestService(t, new(pgxpool.Pool), new(auth.Service)), back, http.StatusBadRequest},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/saml/acs/x", nil)
		(&Handler{Service: tc.service}).acsFailed(rec, req, uuid.New(), tc.returnTo, ErrResponseMissing)
		if rec.Code != tc.want {
			t.Errorf("%s: %d %s, want %d", tc.name, rec.Code, rec.Body.String(), tc.want)
			continue
		}
		if tc.want != http.StatusFound {
			continue
		}
		want := accounts + "/sign-in?" + url.Values{"error": {"sso"}, "return_to": {back}}.Encode()
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("%s: to %s, want %s", tc.name, got, want)
		}
		if strings.Contains(rec.Body.String(), CodeResponseMissing) {
			t.Errorf("%s: the redirect names the detail: %s", tc.name, rec.Body.String())
		}
	}
}
