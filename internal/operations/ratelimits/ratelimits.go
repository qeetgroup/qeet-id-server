// Package ratelimits exposes per-tenant rate limit overrides over HTTP.
// The actual enforcement is done by platform/cache/ratelimit.TenantLimiter;
// this package only owns the CRUD surface (GET/PUT) and delegates mutations
// to the limiter so DB and in-memory cache stay in sync.
package ratelimits

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Limiter is the subset of ratelimit.TenantLimiter used by this package.
type Limiter interface {
	SetOverride(ctx context.Context, tenantID uuid.UUID, rate float64, capacity int) error
	DeleteOverride(ctx context.Context, tenantID uuid.UUID) error
	GetAll(ctx context.Context, pool *pgxpool.Pool) ([]ratelimit.TenantLimit, error)
}

// Defaults are the platform-level fallback values shown in the UI when no
// tenant override exists.
type Defaults struct {
	TenantRate     float64
	TenantCapacity int
	UserRate       float64
	UserCapacity   int
	APIKeyRate     float64
	APIKeyCapacity int
}

type Handler struct {
	Pool      *pgxpool.Pool
	TenantLim Limiter
	UserLim   Limiter
	APIKeyLim Limiter
	Defaults  Defaults
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/rate-limits", h.get)
	r.Put("/tenants/{tenantID}/rate-limits", h.put)
	r.Delete("/tenants/{tenantID}/rate-limits", h.del)
}

func requireTenant(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if id != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

type LimitConfig struct {
	Rate     *float64 `json:"rate"`
	Capacity *int     `json:"capacity"`
}

type TenantLimits struct {
	Tenant LimitConfig `json:"tenant"`
	User   LimitConfig `json:"user"`
	APIKey LimitConfig `json:"api_key"`
}

func (h *Handler) effectiveLimits(ctx context.Context, tenantID uuid.UUID) (TenantLimits, error) {
	// Create a lightweight Queries instance bound to the pool. This avoids
	// adding a stored field to Handler (whose struct literal is built in the
	// router composition root without a constructor call).
	q := dbgen.New(h.Pool)
	rows, err := q.GetRateLimitOverrides(ctx, tenantID)
	if err != nil {
		return TenantLimits{}, err
	}

	out := TenantLimits{
		Tenant: LimitConfig{Rate: &h.Defaults.TenantRate, Capacity: &h.Defaults.TenantCapacity},
		User:   LimitConfig{Rate: &h.Defaults.UserRate, Capacity: &h.Defaults.UserCapacity},
		APIKey: LimitConfig{Rate: &h.Defaults.APIKeyRate, Capacity: &h.Defaults.APIKeyCapacity},
	}
	for _, row := range rows {
		r, c := row.Rate, int(row.Capacity)
		switch row.LimitKey {
		case "tenant":
			out.Tenant = LimitConfig{Rate: &r, Capacity: &c}
		case "user":
			out.User = LimitConfig{Rate: &r, Capacity: &c}
		case "api_key":
			out.APIKey = LimitConfig{Rate: &r, Capacity: &c}
		}
	}
	return out, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limits, err := h.effectiveLimits(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, limits)
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in TenantLimits
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	if in.Tenant.Rate != nil && in.Tenant.Capacity != nil {
		if err := h.TenantLim.SetOverride(ctx, tenantID, *in.Tenant.Rate, *in.Tenant.Capacity); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if in.User.Rate != nil && in.User.Capacity != nil {
		if err := h.UserLim.SetOverride(ctx, tenantID, *in.User.Rate, *in.User.Capacity); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if in.APIKey.Rate != nil && in.APIKey.Capacity != nil {
		if err := h.APIKeyLim.SetOverride(ctx, tenantID, *in.APIKey.Rate, *in.APIKey.Capacity); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	limits, err := h.effectiveLimits(ctx, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, limits)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	for _, lim := range []Limiter{h.TenantLim, h.UserLim, h.APIKeyLim} {
		if err := lim.DeleteOverride(ctx, tenantID); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
