// Package ratelimits exposes per-tenant rate limit overrides over HTTP.
// The actual enforcement is done by platform/cache/ratelimit.TenantLimiter;
// this package only owns the CRUD surface (GET/PUT) and delegates mutations
// to the limiter so DB and in-memory cache stay in sync.
package ratelimits

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/ratelimits/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/cache/ratelimit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Limiter is the subset of ratelimit.TenantLimiter used by this package.
type Limiter interface {
	ApplyOverride(tenantID uuid.UUID, rate float64, capacity int)
	ClearOverride(tenantID uuid.UUID)
	GetAll(ctx context.Context, pool *pgxpool.Pool) ([]ratelimit.TenantLimit, error)
}

func actorOf(r *http.Request) audit.Actor {
	actor := audit.Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if principal := httpx.PrincipalFromCtx(r.Context()); principal != nil {
		actor.UserID = principal.UserID
		if principal.ActorType != "" {
			actor.Type = principal.ActorType
		}
	}
	return actor
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

// MinRate is the lowest override rate, one request every 100 seconds; a bucket
// that refills slower would outlive any store's expiry.
const MinRate = 0.01

// check refuses an override outside [MinRate, rate] requests a second or
// [1, capacity] burst: an organisation may tighten its limits, never lift them
// above the platform's, which protect every organisation sharing it.
func (c LimitConfig) check(key string, rate float64, capacity int) error {
	if c.Rate == nil || c.Capacity == nil {
		return nil
	}
	if *c.Rate < MinRate || *c.Rate > rate || *c.Capacity < 1 || *c.Capacity > capacity {
		return errs.ErrUnprocessable.WithDetail(fmt.Sprintf(
			"%s: rate must be between %g and %g, capacity between 1 and %d", key, MinRate, rate, capacity))
	}
	return nil
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
	d := h.Defaults
	for _, err := range []error{
		in.Tenant.check("tenant", d.TenantRate, d.TenantCapacity),
		in.User.check("user", d.UserRate, d.UserCapacity),
		in.APIKey.check("api_key", d.APIKeyRate, d.APIKeyCapacity),
	} {
		if err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	ctx := r.Context()
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	type appliedOverride struct {
		key      string
		limiter  Limiter
		rate     float64
		capacity int
	}
	var applied []appliedOverride
	metadata := map[string]any{}
	store := func(key string, limiter Limiter, cfg LimitConfig) error {
		if cfg.Rate == nil || cfg.Capacity == nil {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO platform.rate_limit_overrides (tenant_id, limit_key, rate, capacity, updated_at)
			VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (tenant_id, limit_key) DO UPDATE SET
			    rate = EXCLUDED.rate, capacity = EXCLUDED.capacity, updated_at = NOW()
		`, tenantID, key, *cfg.Rate, *cfg.Capacity); err != nil {
			return err
		}
		applied = append(applied, appliedOverride{key: key, limiter: limiter, rate: *cfg.Rate, capacity: *cfg.Capacity})
		metadata[key] = map[string]any{"rate": *cfg.Rate, "capacity": *cfg.Capacity}
		return nil
	}
	for _, item := range []struct {
		key string
		lim Limiter
		cfg LimitConfig
	}{{"tenant", h.TenantLim, in.Tenant}, {"user", h.UserLim, in.User}, {"api_key", h.APIKeyLim, in.APIKey}} {
		if err := store(item.key, item.lim, item.cfg); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := audit.Record(ctx, tx, actorOf(r).Event(tenantID, "rate_limits.updated", "tenant", tenantID, metadata)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: tenantID, Topic: "rate-limit.events", EventType: "rate_limits.updated", Payload: map[string]any{"tenant_id": tenantID, "overrides": metadata}}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for _, item := range applied {
		item.limiter.ApplyOverride(tenantID, item.rate, item.capacity)
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
	tx, err := h.Pool.Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM platform.rate_limit_overrides WHERE tenant_id = $1`, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := audit.Record(ctx, tx, actorOf(r).Event(tenantID, "rate_limits.deleted", "tenant", tenantID, nil)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: tenantID, Topic: "rate-limit.events", EventType: "rate_limits.deleted", Payload: map[string]any{"tenant_id": tenantID}}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for _, lim := range []Limiter{h.TenantLim, h.UserLim, h.APIKeyLim} {
		lim.ClearOverride(tenantID)
	}
	w.WriteHeader(http.StatusNoContent)
}
