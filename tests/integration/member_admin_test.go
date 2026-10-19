//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/search"
)

// TestOrganizationsManageTheirMembersNotOtherOrganizationsAccounts pins what an
// organization's admin can do to a user by id. Anyone who belongs to the
// organization (a role here, or here being their home) can be opened, and the
// organization can remove them, which ends their access here only. An
// account-wide action (status, password, MFA, deletion, signing out
// everywhere) stays with the organization the account belongs to: another one
// is told the account is managed elsewhere, and nothing changes. Someone who
// doesn't belong here is not found.
func TestOrganizationsManageTheirMembersNotOtherOrganizationsAccounts(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	google := createTenant(t, ctx, uniqueSlug("member-a"))
	microsoft := createTenant(t, ctx, uniqueSlug("member-b"))
	admin := createUserInTenant(t, ctx, google)
	addTenantMembership(t, ctx, admin, google)

	// ana signed up on her own and joined Google by invitation: no home.
	var ana uuid.UUID
	if err := testPool.QueryRow(ctx,
		`INSERT INTO "user".users (email) VALUES ($1) RETURNING id`, uniqueSlug("ana")+"@example.com").Scan(&ana); err != nil {
		t.Fatalf("create ana: %v", err)
	}
	addTenantMembership(t, ctx, ana, google)
	// bea's account belongs to Microsoft; she also joined Google.
	bea := createUserInTenant(t, ctx, microsoft)
	addTenantMembership(t, ctx, bea, microsoft)
	addTenantMembership(t, ctx, bea, google)
	// cara is Google's own account (admin-created, no role row yet).
	cara := createUserInTenant(t, ctx, google)
	// dan belongs only to Microsoft.
	dan := createUserInTenant(t, ctx, microsoft)
	addTenantMembership(t, ctx, dan, microsoft)

	authSvc := auth.NewService(testPool, user.NewRepository(testPool), mustIssuer())
	for _, tid := range []uuid.UUID{google, microsoft} {
		if _, err := authSvc.IssuePair(ctx, bea, tid, "198.51.100.7", "browser", "password"); err != nil {
			t.Fatalf("sign bea in: %v", err)
		}
	}
	liveSessions := func(t *testing.T, userID, tenantID uuid.UUID) int {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM auth.sessions WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL`,
			userID, tenantID).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		return n
	}

	r := chi.NewRouter()
	r.Use(withPrincipal(admin, google))
	(&user.Handler{Repo: user.NewRepository(testPool), Validate: validator.New()}).Mount(r)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		r.ServeHTTP(rr, req)
		return rr
	}
	code := func(rr *httptest.ResponseRecorder) string {
		var out struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out.Error.Code
	}

	t.Run("members who joined by invitation open from their id", func(t *testing.T) {
		for _, id := range []uuid.UUID{ana, bea} {
			for _, path := range []string{"", "/security", "/sessions", "/access"} {
				if rr := do(http.MethodGet, "/users/"+id.String()+path, ""); rr.Code != http.StatusOK {
					t.Fatalf("GET /users/%s%s: %d %s", id, path, rr.Code, rr.Body.String())
				}
			}
		}
	})

	t.Run("someone who doesn't belong here is not found", func(t *testing.T) {
		if rr := do(http.MethodGet, "/users/"+dan.String(), ""); rr.Code != http.StatusNotFound {
			t.Fatalf("GET dan: %d, want 404", rr.Code)
		}
		if rr := do(http.MethodDelete, "/users/"+dan.String()+"/membership", ""); rr.Code != http.StatusNotFound {
			t.Fatalf("remove dan: %d, want 404", rr.Code)
		}
	})

	t.Run("an account another organization manages can't be changed from here", func(t *testing.T) {
		for _, c := range []struct{ method, path, body string }{
			{http.MethodPatch, "", `{"status":"suspended"}`},
			{http.MethodPost, "/password", `{"password":"Kx7mQ2vLp9Wz!"}`},
			{http.MethodDelete, "/mfa", ""},
			{http.MethodPut, "/mfa-required", `{"required":true}`},
			{http.MethodPost, "/sessions/revoke-all", ""},
			{http.MethodDelete, "", ""},
		} {
			rr := do(c.method, "/users/"+bea.String()+c.path, c.body)
			if rr.Code != http.StatusForbidden || code(rr) != "user.managed_elsewhere" {
				t.Fatalf("%s /users/bea%s: %d %s; want 403 user.managed_elsewhere", c.method, c.path, rr.Code, rr.Body.String())
			}
		}
		var status string
		if err := testPool.QueryRow(ctx, `SELECT status FROM "user".users WHERE id = $1`, bea).Scan(&status); err != nil || status != "active" {
			t.Fatalf("bea's status = %q (%v), want active", status, err)
		}
		if liveSessions(t, bea, microsoft) != 1 || liveSessions(t, bea, google) != 1 {
			t.Fatal("a refused action touched bea's sessions")
		}
	})

	t.Run("the organization still manages its own accounts", func(t *testing.T) {
		if rr := do(http.MethodPatch, "/users/"+cara.String(), `{"status":"suspended"}`); rr.Code != http.StatusOK {
			t.Fatalf("suspend cara: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("its own account is suspended or deleted, not removed", func(t *testing.T) {
		rr := do(http.MethodDelete, "/users/"+cara.String()+"/membership", "")
		if rr.Code != http.StatusConflict || code(rr) != "user.managed_here" {
			t.Fatalf("remove cara: %d %s; want 409 user.managed_here", rr.Code, rr.Body.String())
		}
	})

	t.Run("search finds members who joined by invitation", func(t *testing.T) {
		var email string
		if err := testPool.QueryRow(ctx, `SELECT email FROM "user".users WHERE id = $1`, ana).Scan(&email); err != nil {
			t.Fatalf("read email: %v", err)
		}
		results, _, err := search.NewService(testPool, nil).Search(ctx, google, nil, email, []string{search.TypeUser}, "", 20)
		if err != nil {
			t.Fatalf("search: %v", err)
		}
		for _, res := range results {
			if res.ID == ana {
				return
			}
		}
		t.Fatalf("search for %s found %v, not ana", email, results)
	})

	t.Run("removing a member ends their access here and only here", func(t *testing.T) {
		rr := do(http.MethodDelete, "/users/"+bea.String()+"/membership", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("remove bea: %d %s", rr.Code, rr.Body.String())
		}
		var roles int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM rbac.user_roles WHERE user_id = $1 AND tenant_id = $2`, bea, google).Scan(&roles); err != nil {
			t.Fatalf("count roles: %v", err)
		}
		if roles != 0 {
			t.Fatalf("bea still holds %d role(s) in the organization", roles)
		}
		if liveSessions(t, bea, google) != 0 {
			t.Fatal("bea's session in the organization is still live")
		}
		if liveSessions(t, bea, microsoft) != 1 {
			t.Fatal("removing bea here ended her session in her own organization")
		}
		var audited int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'user.removed_from_organization'
			    AND actor_user_id = $2 AND resource_id = $3`, google, admin, bea).Scan(&audited); err != nil {
			t.Fatalf("count audit: %v", err)
		}
		if audited != 1 {
			t.Fatalf("removal audit rows = %d, want 1", audited)
		}
		if rr := do(http.MethodGet, "/users/"+bea.String(), ""); rr.Code != http.StatusNotFound {
			t.Fatalf("GET bea after removal: %d, want 404", rr.Code)
		}
	})
}
