//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestSuspendingAnOrganisationCutsOffAccess: suspending or deleting an
// organisation changed its row and nothing else — every member already signed
// in kept working sessions and refresh kept minting tokens for it, and nobody
// could tell who had done it. Now suspension and deletion end every session in
// the organisation in the same transaction, refresh and every sign-in refuse a
// non-active organisation, and each transition is audited with its actor.
func TestSuspendingAnOrganisationCutsOffAccess(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	authSvc, _ := newAuth()
	operator := uuid.New()
	h := &tenant.Handler{Repo: tenant.NewRepository(testPool), Validate: validator.New(), AuthService: authSvc}
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{ActorType: "user", UserID: &operator})))
		})
	})
	router.Route("/v1", h.Mount)
	call := func(t *testing.T, method, path, body string) {
		t.Helper()
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
		if rr.Code >= 300 {
			t.Fatalf("%s %s = %d %s", method, path, rr.Code, rr.Body.String())
		}
	}
	member := func(t *testing.T, org uuid.UUID) (uuid.UUID, *auth.TokenPair) {
		t.Helper()
		id := createUserInTenant(t, ctx, org)
		addTenantMembership(t, ctx, id, org)
		pair, err := authSvc.IssuePair(ctx, id, org, "203.0.113.40", "browser", "password")
		if err != nil {
			t.Fatal(err)
		}
		return id, pair
	}
	refresh := func(pair *auth.TokenPair) error {
		_, err := authSvc.Refresh(ctx, auth.RefreshInput{RefreshToken: pair.RefreshToken, IP: "203.0.113.40", UserAgent: "browser"})
		return err
	}
	revoked := func(t *testing.T, sessionID uuid.UUID) bool {
		t.Helper()
		var r bool
		if err := testPool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM auth.sessions WHERE id = $1`, sessionID).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	audited := func(t *testing.T, org uuid.UUID, action, status string) {
		t.Helper()
		var n int
		if err := testPool.QueryRow(ctx, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = $2
			AND actor_user_id = $3 AND metadata->>'status' = $4`, org, action, operator, status).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s audit rows = %d (%v), want one naming the operator and status %s", action, n, err, status)
		}
	}

	t.Run("suspending ends its sessions, refresh is refused, and reactivating lets members back in", func(t *testing.T) {
		org := createTenant(t, ctx, uniqueSlug("suspended"))
		mo, pair := member(t, org)
		call(t, http.MethodPatch, "/v1/tenants/"+org.String(), `{"status":"suspended"}`)
		if !revoked(t, pair.SessionID) {
			t.Fatal("the member's session outlived the suspension")
		}
		if err := refresh(pair); err == nil {
			t.Fatal("refresh after the suspension issued new tokens")
		}
		if _, err := authSvc.IssuePair(ctx, mo, org, "203.0.113.40", "browser", "password"); !errors.Is(err, errs.ErrAuthTenantInactive) {
			t.Fatalf("sign-in to the suspended organisation = %v, want auth.tenant_inactive", err)
		}
		home, err := authSvc.IssuePair(ctx, mo, uuid.Nil, "203.0.113.40", "browser", "password")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authSvc.SwitchTenant(ctx, auth.SwitchTenantInput{UserID: mo, FromSessionID: home.SessionID, TenantID: org, IP: "203.0.113.40", UserAgent: "browser"}); err == nil {
			t.Fatal("switching into the suspended organisation succeeded")
		}
		audited(t, org, "tenant.suspended", "suspended")

		call(t, http.MethodPatch, "/v1/tenants/"+org.String(), `{"status":"active"}`)
		if _, err := authSvc.IssuePair(ctx, mo, org, "203.0.113.40", "browser", "password"); err != nil {
			t.Fatalf("sign-in after reactivation: %v", err)
		}
		audited(t, org, "tenant.reactivated", "active")
	})

	t.Run("a suspension made directly in the database still stops refresh", func(t *testing.T) {
		org := createTenant(t, ctx, uniqueSlug("billing-suspended"))
		_, pair := member(t, org)
		if _, err := testPool.Exec(ctx, `UPDATE tenant.tenants SET status = 'suspended' WHERE id = $1`, org); err != nil {
			t.Fatal(err)
		}
		if err := refresh(pair); !errors.Is(err, errs.ErrAuthTenantInactive) {
			t.Fatalf("refresh = %v, want auth.tenant_inactive", err)
		}
	})

	t.Run("deleting ends its sessions and nobody gets a token for it", func(t *testing.T) {
		org := createTenant(t, ctx, uniqueSlug("deleted"))
		mo, pair := member(t, org)
		call(t, http.MethodDelete, "/v1/tenants/"+org.String(), "")
		if !revoked(t, pair.SessionID) {
			t.Fatal("the member's session outlived the deletion")
		}
		if err := refresh(pair); err == nil {
			t.Fatal("refresh after the deletion issued new tokens")
		}
		if _, err := authSvc.IssuePair(ctx, mo, org, "203.0.113.40", "browser", "password"); !errors.Is(err, errs.ErrAuthTenantInactive) {
			t.Fatalf("sign-in to the deleted organisation = %v, want auth.tenant_inactive", err)
		}
		audited(t, org, "tenant.deleted", "deleted")
	})
}
