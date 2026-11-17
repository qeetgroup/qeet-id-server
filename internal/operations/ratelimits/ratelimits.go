// Package ratelimits exposes per-organization rate limit overrides over HTTP.
// The actual enforcement is done by platform/cache/ratelimit.OrganizationLimiter;
// this package only owns the CRUD surface (GET/PUT) and delegates mutations
// to the limiter so DB and in-memory cache stay in sync.
package ratelimits

import (
	"context"
	"encoding/json"
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

// Limiter is the subset of ratelimit.OrganizationLimiter used by this package.
type Limiter interface {
	ApplyOverride(organizationID uuid.UUID, rate float64, capacity int)
	ClearOverride(organizationID uuid.UUID)
	GetAll(ctx context.Context, pool *pgxpool.Pool) ([]ratelimit.OrganizationLimit, error)
}

// Defaults are the platform-level fallback values shown in the UI when no
// organization override exists.
type Defaults struct {
	OrganizationRate     float64
	OrganizationCapacity int
	UserRate             float64
	UserCapacity         int
	APIKeyRate           float64
	APIKeyCapacity       int
}

// Bucket is a token bucket: Rate requests a second, bursts of Capacity.
type Bucket struct {
	Rate     float64 `json:"rate"`
	Capacity int     `json:"capacity"`
}

// BuiltInLimit is one of the platform's fixed limits, the same for every
// organization: Per says whose requests share a bucket (ip, user or address).
type BuiltInLimit struct {
	Name    string `json:"name"`
	Per     string `json:"per"`
	Applies string `json:"applies"`
	Bucket
}

// Handler serves the rate-limit override HTTP API.
type Handler struct {
	Pool            *pgxpool.Pool
	OrganizationLim Limiter
	UserLim         Limiter
	APIKeyLim       Limiter
	Defaults        Defaults
	BuiltIn         []BuiltInLimit // reported, read-only
}

// Mount registers the rate-limit override routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/rate-limits", h.get)
	r.Put("/tenants/{tenantID}/rate-limits", h.put)
	r.Delete("/tenants/{tenantID}/rate-limits", h.del)
}

func requireOrganization(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireOrganization(r)
	if err != nil {
		return uuid.Nil, err
	}
	if id != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

// LimitConfig is a bucket's rate (requests a second) and capacity (burst).
type LimitConfig struct {
	Rate     *float64 `json:"rate"`
	Capacity *int     `json:"capacity"`
}

// MinRate is the lowest override rate, one request every 100 seconds; a bucket
// that refills slower would outlive any store's expiry.
const MinRate = 0.01

// check refuses an override outside [MinRate, rate] requests a second or
// [1, capacity] burst: an organization may tighten its limits, never lift them
// above the platform's, which protect every organization sharing it.
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

// OrganizationLimits is an organization's limits per organization, user and API key.
type OrganizationLimits struct {
	Organization LimitConfig `json:"tenant"`
	User         LimitConfig `json:"user"`
	APIKey       LimitConfig `json:"api_key"`
}

// limitsView is an organization's effective limits with what bounds them: the
// platform defaults, which are also the ceiling an override may reach, the
// lowest rate an override may set, and the built-in limits.
type limitsView struct {
	OrganizationLimits
	Defaults bucketsView    `json:"defaults"`
	Ceiling  bucketsView    `json:"ceiling"`
	MinRate  float64        `json:"min_rate"`
	BuiltIn  []BuiltInLimit `json:"built_in"`
}

// limitsInput is a PUT body: the overrides, and the read-only bounds a body
// read back from GET carries, which are ignored.
type limitsInput struct {
	OrganizationLimits
	Defaults json.RawMessage `json:"defaults"`
	Ceiling  json.RawMessage `json:"ceiling"`
	MinRate  json.RawMessage `json:"min_rate"`
	BuiltIn  json.RawMessage `json:"built_in"`
}

// bucketsView is a value per organization, person and API-key bucket.
type bucketsView struct {
	Organization Bucket `json:"tenant"`
	User         Bucket `json:"user"`
	APIKey       Bucket `json:"api_key"`
}

// view adds the bounds to limits.
func (h *Handler) view(limits OrganizationLimits) limitsView {
	d := bucketsView{
		Organization: Bucket{Rate: h.Defaults.OrganizationRate, Capacity: h.Defaults.OrganizationCapacity},
		User:         Bucket{Rate: h.Defaults.UserRate, Capacity: h.Defaults.UserCapacity},
		APIKey:       Bucket{Rate: h.Defaults.APIKeyRate, Capacity: h.Defaults.APIKeyCapacity},
	}
	builtIn := h.BuiltIn
	if builtIn == nil {
		builtIn = []BuiltInLimit{}
	}
	return limitsView{OrganizationLimits: limits, Defaults: d, Ceiling: d, MinRate: MinRate, BuiltIn: builtIn}
}

func (h *Handler) effectiveLimits(ctx context.Context, organizationID uuid.UUID) (OrganizationLimits, error) {
	// Create a lightweight Queries instance bound to the pool. This avoids
	// adding a stored field to Handler (whose struct literal is built in the
	// router composition root without a constructor call).
	q := dbgen.New(h.Pool)
	rows, err := q.GetRateLimitOverrides(ctx, organizationID)
	if err != nil {
		return OrganizationLimits{}, err
	}

	out := OrganizationLimits{
		Organization: LimitConfig{Rate: &h.Defaults.OrganizationRate, Capacity: &h.Defaults.OrganizationCapacity},
		User:         LimitConfig{Rate: &h.Defaults.UserRate, Capacity: &h.Defaults.UserCapacity},
		APIKey:       LimitConfig{Rate: &h.Defaults.APIKeyRate, Capacity: &h.Defaults.APIKeyCapacity},
	}
	for _, row := range rows {
		r, c := row.Rate, int(row.Capacity)
		switch row.LimitKey {
		case "tenant":
			out.Organization = LimitConfig{Rate: &r, Capacity: &c}
		case "user":
			out.User = LimitConfig{Rate: &r, Capacity: &c}
		case "api_key":
			out.APIKey = LimitConfig{Rate: &r, Capacity: &c}
		}
	}
	return out, nil
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limits, err := h.effectiveLimits(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(limits))
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body limitsInput
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in := body.OrganizationLimits
	d := h.Defaults
	for _, err := range []error{
		in.Organization.check("tenant", d.OrganizationRate, d.OrganizationCapacity),
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
			INSERT INTO platform.rate_limit_overrides (organization_id, limit_key, rate, capacity, updated_at)
			VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (organization_id, limit_key) DO UPDATE SET
			    rate = EXCLUDED.rate, capacity = EXCLUDED.capacity, updated_at = NOW()
		`, organizationID, key, *cfg.Rate, *cfg.Capacity); err != nil {
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
	}{{"tenant", h.OrganizationLim, in.Organization}, {"user", h.UserLim, in.User}, {"api_key", h.APIKeyLim, in.APIKey}} {
		if err := store(item.key, item.lim, item.cfg); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := audit.Record(ctx, tx, audit.ActorOf(r).Event(organizationID, "rate_limits.updated", "tenant", organizationID, metadata)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: organizationID, Topic: "rate-limit.events", EventType: "rate_limits.updated", Payload: map[string]any{"tenant_id": organizationID, "overrides": metadata}}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for _, item := range applied {
		item.limiter.ApplyOverride(organizationID, item.rate, item.capacity)
	}
	limits, err := h.effectiveLimits(ctx, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(limits))
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requireOrganization(r)
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
	if _, err := tx.Exec(ctx, `DELETE FROM platform.rate_limit_overrides WHERE organization_id = $1`, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := audit.Record(ctx, tx, audit.ActorOf(r).Event(organizationID, "rate_limits.deleted", "tenant", organizationID, nil)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: organizationID, Topic: "rate-limit.events", EventType: "rate_limits.deleted", Payload: map[string]any{"tenant_id": organizationID}}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	for _, lim := range []Limiter{h.OrganizationLim, h.UserLim, h.APIKeyLim} {
		lim.ClearOverride(organizationID)
	}
	w.WriteHeader(http.StatusNoContent)
}
