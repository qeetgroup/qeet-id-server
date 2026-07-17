package httpx_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
	"github.com/qeetgroup/qeet-id/platform/security/tokens"
)

// TestEnforceTenantScope locks in the central cross-tenant guard (QID-18): a
// request to /tenants/{tenantID}/... must be rejected with 403 unless the path
// tenant equals the caller's own tenant; routes without a {tenantID} param pass
// through. Uses a real chi router so the {tenantID} param is actually extracted
// the same way it is in production (the guard reads chi.URLParam).
func TestEnforceTenantScope(t *testing.T) {
	callerTenant := uuid.New()
	otherTenant := uuid.New()
	uid := uuid.New()

	// Mirror the production router structure exactly (nested Route + Group with
	// the guard as group middleware) — chi only populates {tenantID} for a
	// group-level middleware when routes are matched by a nested subrouter, so a
	// flat mux would not exercise the same code path the server uses.
	newRouter := func() *chi.Mux {
		r := chi.NewRouter()
		r.Route("/v1", func(r chi.Router) {
			r.Group(func(r chi.Router) {
				r.Use(func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						p := &httpx.Principal{UserID: &uid, TenantID: &callerTenant}
						next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
					})
				})
				r.Use(httpx.EnforceTenantScope)
				ok := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
				r.Get("/tenants/{tenantID}/roles", ok)
				r.Get("/users/{id}", ok) // no tenantID param — must pass through
			})
		})
		return r
	}

	cases := []struct {
		name string
		path string
		want int
	}{
		{"own tenant allowed", "/v1/tenants/" + callerTenant.String() + "/roles", http.StatusOK},
		{"cross tenant forbidden", "/v1/tenants/" + otherTenant.String() + "/roles", http.StatusForbidden},
		{"malformed tenant rejected", "/v1/tenants/not-a-uuid/roles", http.StatusBadRequest},
		{"no tenant param passes through", "/v1/users/" + uuid.New().String(), http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newRouter().ServeHTTP(w, httptest.NewRequest("GET", tc.path, nil))
			if w.Code != tc.want {
				t.Fatalf("%s: got %d, want %d", tc.path, w.Code, tc.want)
			}
		})
	}
}

// TestRequireAuth_AgentStatusEnforced locks in the AI-agent kill-switch: an
// agent token is stateless and stays cryptographically valid until it expires,
// so revocation is enforced at request time by consulting the agent's current
// lifecycle status. A suspended/decommissioned/unknown agent must be denied
// with 401 immediately (within one request), never reaching the handler; an
// active agent must pass through. This guards against a refactor silently
// dropping the AgentStatus check (which would make suspend/kill-all a no-op
// until token expiry).
func TestRequireAuth_AgentStatusEnforced(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	iss, err := tokens.NewIssuer(keyPEM, "qeet-test", "qeet-test", time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	tenantID, agentID := uuid.New(), uuid.New()
	now := time.Now()
	// Mint an agent access token the way the agents service does: a normal ES256
	// access token additionally carrying actor_type=agent + agent_id.
	agentTok, err := iss.Sign(jwt.MapClaims{
		"iss":        "qeet-test",
		"aud":        "qeet-test",
		"sub":        agentID.String(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        now.Add(time.Hour).Unix(),
		"jti":        uuid.NewString(),
		"tenant_id":  tenantID.String(),
		"scope":      "openid",
		"actor_type": "agent",
		"agent_id":   agentID.String(),
	})
	if err != nil {
		t.Fatalf("sign agent token: %v", err)
	}

	cases := []struct {
		name        string
		status      string
		statusErr   error
		wantCode    int
		wantReached bool
	}{
		{"active agent passes", "active", nil, http.StatusOK, true},
		{"suspended agent denied", "suspended", nil, http.StatusUnauthorized, false},
		{"decommissioned agent denied", "decommissioned", nil, http.StatusUnauthorized, false},
		{"unknown agent denied", "", errors.New("not found"), http.StatusUnauthorized, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			v := &httpx.AuthVerifier{
				Tokens: iss,
				AgentStatus: func(_ context.Context, id uuid.UUID) (string, error) {
					if id != agentID {
						t.Fatalf("AgentStatus called with %s, want %s", id, agentID)
					}
					return tc.status, tc.statusErr
				},
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				if p := httpx.PrincipalFromCtx(r.Context()); p == nil || p.ActorType != "agent" {
					t.Errorf("handler principal = %+v, want actor_type=agent", p)
				}
				w.WriteHeader(http.StatusOK)
			})

			w := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/v1/anything", nil)
			req.Header.Set("Authorization", "Bearer "+agentTok)
			httpx.RequireAuth(v)(next).ServeHTTP(w, req)

			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body: %s)", w.Code, tc.wantCode, w.Body.String())
			}
			if reached != tc.wantReached {
				t.Fatalf("handler reached = %v, want %v", reached, tc.wantReached)
			}
		})
	}
}

func TestRequireTenant(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"tenant present", &httpx.Principal{UserID: &uid, TenantID: &tid}, tid, false},
		{"tenant-less principal", &httpx.Principal{UserID: &uid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireTenant(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got tenant %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}

func TestRequireUser(t *testing.T) {
	tid := uuid.New()
	uid := uuid.New()
	cases := []struct {
		name    string
		p       *httpx.Principal
		want    uuid.UUID
		wantErr bool
	}{
		{"user present", &httpx.Principal{UserID: &uid, TenantID: &tid}, uid, false},
		{"user-less principal", &httpx.Principal{TenantID: &tid}, uuid.Nil, true},
		{"no principal", nil, uuid.Nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tc.p != nil {
				r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.p))
			}
			got, err := httpx.RequireUser(r)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got user %s", got)
			}
			if !tc.wantErr && (err != nil || got != tc.want) {
				t.Fatalf("got (%s, %v), want (%s, nil)", got, err, tc.want)
			}
		})
	}
}
