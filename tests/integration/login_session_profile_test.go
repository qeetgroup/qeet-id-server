//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/bootstrap"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestHostedLoginSessionReadsItsOwnProfile (QTID-532): a browser holding only
// the hosted login's session cookie, as the React SDK does, reads who it is
// (GET /v1/auth/me, GET /v1/me) and the organisations it belongs to, by name
// (GET /v1/me/organizations). Before, every one answered 401, so useUser had
// no profile and the organisation switcher showed one raw id. The cookie still
// opens nothing else: an unlisted route stays token-only.
func TestHostedLoginSessionReadsItsOwnProfile(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	issuer := mustIssuer()
	authSvc := auth.NewService(testPool, user.NewRepository(testPool), issuer)
	orgA := createTenant(t, ctx, uniqueSlug("cookie-a"))
	orgB := createTenant(t, ctx, uniqueSlug("cookie-b"))
	ana := createUserInTenant(t, ctx, orgA)
	addTenantMembership(t, ctx, ana, orgA)
	addTenantMembership(t, ctx, ana, orgB)

	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Use(authSvc.LoginSessionAuth(bootstrap.LoginSessionRoutes()))
		r.Use(httpx.RequireAuth(&httpx.AuthVerifier{Tokens: issuer}))
		(&auth.Handler{Service: authSvc, Validate: validator.New()}).MountAuthed(r)
		(&user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New(), SignIns: authSvc}).Mount(r)
		(&tenant.Handler{Repo: tenant.NewRepository(testPool), Validate: validator.New(), AuthService: authSvc}).Mount(r)
	})
	cookie, err := authSvc.CreateLoginSession(ctx, ana, "203.0.113.7", uaChromeMac)
	if err != nil {
		t.Fatalf("hosted-login session: %v", err)
	}
	get := func(path string, withCookie bool) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if withCookie {
			req.AddCookie(&http.Cookie{Name: auth.LoginSessionCookie, Value: cookie})
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		out := map[string]any{}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return rr.Code, out
	}

	if code, out := get("/v1/auth/me", true); code != http.StatusOK || out["user_id"] != ana.String() {
		t.Fatalf("GET /v1/auth/me with the cookie = %d %v, want 200 naming the user", code, out)
	}
	if code, out := get("/v1/me", true); code != http.StatusOK || out["id"] != ana.String() || out["email"] == nil {
		t.Fatalf("GET /v1/me with the cookie = %d %v, want the profile", code, out)
	}
	code, out := get("/v1/me/organizations", true)
	items, _ := out["items"].([]any)
	if code != http.StatusOK || len(items) != 2 {
		t.Fatalf("GET /v1/me/organizations with the cookie = %d %v, want both organisations", code, out)
	}
	for _, it := range items {
		if name, _ := it.(map[string]any)["name"].(string); name == "" {
			t.Fatalf("organisation without a name: %v", it)
		}
	}

	if code, _ := get("/v1/me", false); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/me with no cookie = %d, want 401", code)
	}
	if code, _ := get("/v1/auth/sessions", true); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/auth/sessions with only the cookie = %d, want 401 (not a hosted-login route)", code)
	}
}
