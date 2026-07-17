//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id/domains/operations/ratelimits"
	"github.com/qeetgroup/qeet-id/platform/api/rest/httpx"
)

// Rate-limit overrides: GET returns platform defaults when no override exists,
// reflects a per-tenant override once set, and rejects a cross-tenant request.
// Exercises the real handler (effectiveLimits merge + requireTenant scope guard)
// through a router shaped like production (nested /v1 + {tenantID} + principal).
func TestRateLimits_EffectiveDefaultsOverrideAndScope(t *testing.T) {
	requireDB(t)
	ctx := context.Background()
	tid := createTenant(t, ctx, uniqueSlug("rl"))
	uid := createTenantUser(t, ctx, tid, uniqueSlug("rluser")+"@example.com")

	h := &ratelimits.Handler{
		Pool: testPool,
		Defaults: ratelimits.Defaults{
			TenantRate: 100, TenantCapacity: 500,
			UserRate: 30, UserCapacity: 100,
			APIKeyRate: 50, APIKeyCapacity: 200,
		},
	}
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					p := &httpx.Principal{UserID: &uid, TenantID: &tid}
					next.ServeHTTP(w, req.WithContext(httpx.WithPrincipal(req.Context(), p)))
				})
			})
			h.Mount(r)
		})
	})

	getLimits := func() ratelimits.TenantLimits {
		t.Helper()
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/v1/tenants/"+tid.String()+"/rate-limits", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET rate-limits: %d (%s)", w.Code, w.Body.String())
		}
		var out ratelimits.TenantLimits
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	// 1. No override → platform defaults.
	def := getLimits()
	if def.Tenant.Rate == nil || *def.Tenant.Rate != 100 || def.Tenant.Capacity == nil || *def.Tenant.Capacity != 500 {
		t.Fatalf("defaults: tenant = %+v, want rate=100 cap=500", def.Tenant)
	}
	if def.User.Rate == nil || *def.User.Rate != 30 {
		t.Fatalf("defaults: user rate = %v, want 30", def.User.Rate)
	}

	// 2. Per-tenant override → GET reflects it; unset keys stay on defaults.
	if _, err := testPool.Exec(ctx,
		`INSERT INTO platform.rate_limit_overrides (tenant_id, limit_key, rate, capacity) VALUES ($1, 'tenant', 7, 42)`,
		tid); err != nil {
		t.Fatalf("insert override: %v", err)
	}
	over := getLimits()
	if over.Tenant.Rate == nil || *over.Tenant.Rate != 7 || over.Tenant.Capacity == nil || *over.Tenant.Capacity != 42 {
		t.Fatalf("override: tenant = %+v, want rate=7 cap=42", over.Tenant)
	}
	if over.User.Capacity == nil || *over.User.Capacity != 100 {
		t.Fatalf("override: user cap = %v, want default 100 (unchanged)", over.User.Capacity)
	}

	// 3. Cross-tenant scope guard: another tenant's limits → 403.
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/v1/tenants/"+uuid.New().String()+"/rate-limits", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant GET = %d, want 403", w.Code)
	}
}
